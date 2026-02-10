package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.controllers.PasskeyController
import com.gu.playpasskeyauth.filters.PasskeyVerificationFilter
import com.gu.playpasskeyauth.models.{HostApp, User, WebAuthnConfig}
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
  *   The user type for which a [[UserIdExtractor]] must be available. You must provide an implicit function to extract
  *   user IDs:
  *   {{{
  * case class MyUser(email: String, name: String)
  * given UserIdExtractor[MyUser] = user => UserId(user.email)
  *   }}}
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
  * @param ctx
  *   Context
  *
  * @param passkeyRepo
  *   Repository for storing passkey credentials. You must implement [[PasskeyRepository]] for your storage backend
  *   (e.g., PostgreSQL, DynamoDB)
  *
  * @param challengeRepo
  *   Repository for storing temporary challenges. You must implement [[PasskeyChallengeRepository]] (can be in-memory
  *   for development, or Redis/database for production)
  *
  * @param registrationRedirect
  *   Where to redirect after successful passkey registration. Example: `routes.AccountController.settings()`
  *
  * Context parameters (provided via `using` clause):
  *   - `ExecutionContext`: Required for asynchronous operations
  *   - `PasskeyAuthContext[U, B]`: A typeclass that bundles together all authentication-related components:
  *     - User type constraint (`User[U]`)
  *     - User action builder for extracting authenticated users
  *     - Creation data extractor for `navigator.credentials.create()` responses
  *     - Authentication data extractor for `navigator.credentials.get()` responses
  *     - Passkey name extractor for user-provided passkey names
  *     - WebAuthn configuration (algorithms, timeouts, authenticator selection, etc.)
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
  *   // Define the extractors
  *   given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *   given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *   given PasskeyNameExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *
  *   // Create the user action by composing auth with user extraction
  *   val userExtractor: UserExtractor[MyUser, AuthenticatedRequest] = _.user
  *   val userAction = authAction.andThen(new UserAction(userExtractor))
  *
  *   // Bundle all authentication components into a single context
  *   given PasskeyAuthContext[MyUser, AnyContent] = PasskeyAuthContext(
  *     userAction = userAction,
  *     creationDataExtractor = summon,
  *     authenticationDataExtractor = summon,
  *     passkeyNameExtractor = summon
  *   )
  *
  *   // Now PasskeyAuth only needs the core dependencies
  *   val passkeyAuth = new PasskeyAuth[MyUser, AnyContent](
  *     cc,
  *     HostApp("My App", new URI("https://myapp.example.com")),
  *     passkeyRepo,
  *     challengeRepo,
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
// TODO: expose traits: Controller, VerificationService, Logic, Filter - calling code where these are used can just have one of these traits as param
class PasskeyAuth[U: User, B](
    controllerComponents: ControllerComponents,
    app: HostApp,
    ctx: PasskeyAuthContext[U, B],
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    registrationRedirect: Call
)(using ExecutionContext) {
  // TODO: instead of exposing the verification service expose its methods and then implement its methods directly in this class
  val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(app, passkeyRepo, challengeRepo, ctx.webAuthnConfig)

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
    val authDataAction = new AuthenticationDataAction[U](ctx.authenticationDataExtractor)
    val verificationFilter = new PasskeyVerificationFilter[U](verificationService)
    ctx.userAction.andThen(authDataAction).andThen(verificationFilter)
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
    new PasskeyController[U, B](
      controllerComponents,
      ctx,
      verificationService,
      registrationRedirect
    )
  }
}
