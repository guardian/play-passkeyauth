package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.controllers.PasskeyController
import com.gu.playpasskeyauth.filters.PasskeyVerificationFilter
import com.gu.playpasskeyauth.models.{HostApp, PasskeyUser, WebAuthnConfig}
import com.gu.playpasskeyauth.services.{
  PasskeyChallengeRepository,
  PasskeyRepository,
  PasskeyVerificationService,
  PasskeyVerificationServiceImpl
}
import com.gu.playpasskeyauth.web.*
import play.api.mvc.{ActionBuilder, Call, ControllerComponents}

import scala.concurrent.ExecutionContext

/** Main entry point for integrating passkey authentication into a Play application.
  *
  * This class wires together all the components needed for WebAuthn/passkey authentication: controllers, action
  * builders, and verification filters. It provides factory methods to create the controller for passkey management and
  * action builders for protecting routes.
  *
  * @tparam U
  *   The user type, which must have a [[PasskeyUser]] type class instance.
  *
  * @tparam B
  *   The body content type (typically `AnyContent`)
  *
  * @param controllerComponents
  *   Play's controller components for request handling
  *
  * @param app
  *   The [[HostApp]] configuration identifying your application (relying party).
  *
  * @param userAction
  *   An action builder that extracts the authenticated user. Client code is responsible for ensuring the user is signed
  *   in before this action runs. Typically created by composing your authentication action with [[UserAction]]:
  *   {{{
  *   val userAction = authAction.andThen(new UserAction(myUserExtractor))
  *   }}}
  *
  * @param passkeyRepo
  *   Repository for storing passkey credentials. You must implement [[PasskeyRepository]] for your storage backend
  *   (e.g., PostgreSQL, DynamoDB)
  *
  * @param challengeRepo
  *   Repository for storing temporary challenges. You must implement [[PasskeyChallengeRepository]] (can be in-memory
  *   for development, or Redis/database for production)
  *
  * @param creationDataExtractor
  *   Strategy for extracting passkey creation data from requests. This data comes from `navigator.credentials.create()`
  *   in the browser.
  *
  * @param authenticationDataExtractor
  *   Strategy for extracting passkey authentication data from requests. This data comes from
  *   `navigator.credentials.get()` in the browser.
  *
  * @param passkeyNameExtractor
  *   Strategy for extracting the user-provided passkey name from requests.
  *
  * @param registrationRedirect
  *   Where to redirect after successful passkey registration. Example: `routes.AccountController.settings()`
  *
  * @param webAuthnConfig
  *   Configuration for WebAuthn operations (algorithms, timeouts, etc.). Defaults to [[WebAuthnConfig.default]] which
  *   is suitable for most applications.
  *
  * @example
  *   {{{
  * // In your controller or module:
  * class PasskeyModule @Inject()(
  *   cc: ControllerComponents,
  *   authAction: AuthenticatedAction,
  *   passkeyRepo: MyPasskeyRepository,
  *   challengeRepo: MyChallengeRepository
  * )(using ec: ExecutionContext) {
  *
  *   // Create the user action by composing auth with user extraction
  *   val userExtractor: UserExtractor[MyUser, AuthenticatedRequest] = _.user
  *   val userAction = authAction.andThen(new UserAction(userExtractor))
  *
  *   given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *   given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *   given PasskeyNameExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *
  *   val passkeyAuth = new PasskeyAuth[MyUser, AnyContent](
  *     cc,
  *     HostApp("My App", new URI("https://myapp.example.com")),
  *     userAction,
  *     passkeyRepo,
  *     challengeRepo,
  *     creationDataExtractor,
  *     authenticationDataExtractor,
  *     passkeyNameExtractor,
  *     routes.AccountController.settings()
  *   )
  *
  *   // Get the controller for passkey registration endpoints
  *   val controller = passkeyAuth.controller()
  *
  *   // Get an action builder for protecting routes with passkey verification
  *   val verifyAction = passkeyAuth.verificationAction()
  * }
  *   }}}
  */
class PasskeyAuth[U: PasskeyUser, B](
    controllerComponents: ControllerComponents,
    app: HostApp,
    userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], B],
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
    authenticationDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]],
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]],
    registrationRedirect: Call,
    webAuthnConfig: WebAuthnConfig = WebAuthnConfig.default
)(using ExecutionContext) {
  private val verificationService: PasskeyVerificationService[U] =
    new PasskeyVerificationServiceImpl[U](app, passkeyRepo, challengeRepo, webAuthnConfig)

  /** Creates an action builder that verifies passkey authentication.
    *
    * Use this to protect routes that require step-up authentication with a passkey. The action will:
    *   1. Extract the user from the request
    *   2. Extract the authentication data (WebAuthn assertion) from the request
    *   3. Verify the passkey signature against the stored credential
    *
    * If verification fails, a `BadRequest` or `InternalServerError` is returned.
    *
    * @return
    *   An action builder that yields [[RequestWithAuthenticationData]] on success
    *
    * @example
    *   {{{
    * // In your controller:
    * def sensitiveAction = passkeyAuth.verificationAction().async { request =>
    *   // User's passkey has been verified at this point
    *   performSensitiveOperation(request.user)
    * }
    *   }}}
    */
  def verificationAction(): ActionBuilder[[A] =>> RequestWithAuthenticationData[U, A], B] = {
    val authDataAction = new AuthenticationDataAction[U](authenticationDataExtractor)
    val verificationFilter = new PasskeyVerificationFilter[U](verificationService)
    userAction.andThen(authDataAction).andThen(verificationFilter)
  }

  /** Creates a controller for passkey registration and management endpoints.
    *
    * The controller provides endpoints for:
    *   - `creationOptions`: Generate options for `navigator.credentials.create()`
    *   - `register`: Register a new passkey credential
    *   - `authenticationOptions`: Generate options for `navigator.credentials.get()`
    *   - `list`: List all passkeys for the user with metadata
    *   - `delete(passkeyId)`: Delete a passkey by its base64url-encoded ID
    *
    * @return
    *   A configured [[PasskeyController]] instance
    *
    * @example
    *   {{{
    * // In your routes file:
    * POST   /passkey/creation-options  controllers.MyPasskeyController.creationOptions
    * POST   /passkey/register          controllers.MyPasskeyController.register
    * POST   /passkey/auth-options      controllers.MyPasskeyController.authenticationOptions
    * GET    /passkey/list              controllers.MyPasskeyController.list
    * DELETE /passkey/:id               controllers.MyPasskeyController.delete(id)
    *
    * // In your controller:
    * class MyPasskeyController @Inject()(passkeyAuth: PasskeyAuth[...]) {
    *   private val controller = passkeyAuth.controller()
    *   def creationOptions = controller.creationOptions
    *   def register = controller.register
    *   def authenticationOptions = controller.authenticationOptions
    *   def list = controller.list
    *   def delete(id: String) = controller.delete(id)
    * }
    *   }}}
    */
  def controller(): PasskeyController[U, B] = {
    val creationDataAction = new CreationDataAction[U](creationDataExtractor, passkeyNameExtractor)
    val userAndCreationDataAction = userAction.andThen(creationDataAction)
    new PasskeyController[U, B](
      controllerComponents,
      verificationService,
      userAction,
      userAndCreationDataAction,
      registrationRedirect
    )
  }
}
