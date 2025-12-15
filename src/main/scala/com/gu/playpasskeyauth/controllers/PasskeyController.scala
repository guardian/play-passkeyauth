package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.models.{PasskeyId, PasskeyUser}
import com.gu.playpasskeyauth.services.{PasskeyException, PasskeyVerificationService}
import com.gu.playpasskeyauth.web.{RequestWithCreationData, RequestWithUser}
import play.api.Logging
import play.api.libs.json.Writes
import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}

/** Controller for handling passkey registration and verification.
  *
  * This controller provides endpoints for the WebAuthn/passkey authentication flow:
  *   - Generating credential creation options for registering new passkeys
  *   - Registering new passkey credentials
  *   - Generating authentication options for verifying passkeys
  *
  * @tparam U
  *   The user type, which must have a [[PasskeyUser]] type class instance. For example,
  *   `case class MyUser(email: String, name: String)` with an appropriate `given PasskeyUser[MyUser]` in scope.
  *
  * @tparam B
  *   The body content type for the registration action. This is typically the parsed request body type (e.g.,
  *   `AnyContent`, `JsValue`, or a custom type).
  *
  * @param controllerComponents
  *   Play's controller components for request handling
  *
  * @param passkeyService
  *   The service that handles passkey operations (creation, registration, verification)
  *
  * @param userAction
  *   An action builder that extracts the user from the request. This transforms a standard request into a
  *   [[RequestWithUser]] containing the authenticated user. Example implementation:
  *   {{{
  *     // Assuming you have a base action that provides authentication
  *     val userAction = authAction.andThen(new UserAction(myUserExtractor))
  *   }}}
  *
  * @param creationDataAction
  *   An action builder that extracts both the user and the passkey creation data from the request. The creation data
  *   comes from the browser's `navigator.credentials.create()` call. Example:
  *   {{{
  *     val creationDataAction = userAction.andThen(new CreationDataAction(creationDataExtractor, passkeyNameExtractor))
  *   }}}
  *
  * @param registrationRedirect
  *   The [[Call]] to redirect to after successful passkey registration. For example:
  *   `routes.DashboardController.index()` or `Call("GET", "/dashboard")`
  */
class PasskeyController[U: PasskeyUser, B](
    controllerComponents: ControllerComponents,
    passkeyService: PasskeyVerificationService[U],
    userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], B],
    creationDataAction: ActionBuilder[[A] =>> RequestWithCreationData[U, A], B],
    registrationRedirect: Call
)(using val executionContext: ExecutionContext)
    extends AbstractController(controllerComponents)
    with Logging {

  /** Generates the options required to create a new passkey credential.
    *
    * This endpoint should be called before invoking `navigator.credentials.create()` in the browser. The returned
    * options include the relying party information, user details, supported algorithms, and a random challenge for the
    * cryptographic operation.
    *
    * Returns a JSON response with [[com.webauthn4j.data.PublicKeyCredentialCreationOptions]].
    *
    * @see
    *   [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair]]
    *
    * @return
    *   A Play action that returns the creation options as JSON, or an error response
    */
  def creationOptions: Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse(
      "creationOptions",
      request.user,
      passkeyService.buildCreationOptions(request.user)
    )
  }

  /** Registers a new passkey credential for the authenticated user.
    *
    * This endpoint receives the credential created by `navigator.credentials.create()` in the browser. The request must
    * contain:
    *   - The passkey name
    *   - The creation data JSON returned by the browser's WebAuthn API
    *
    * On success, redirects to the configured `registrationRedirect` URL.
    *
    * @see
    *   [[https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server]]
    *
    * @return
    *   A Play action that redirects on success, or returns an error response
    */
  def register: Action[B] = creationDataAction.async { request =>
    apiRedirectResponse(
      "register",
      request.user,
      registrationRedirect,
      passkeyService.register(request.user, request.passkeyName, request.creationData).map(_ => ())
    )
  }

  /** Generates the options required to authenticate with an existing passkey.
    *
    * This endpoint should be called before invoking `navigator.credentials.get()` in the browser. The returned options
    * include a list of allowed credentials for this user and a random challenge for the cryptographic verification.
    *
    * Returns a JSON response with [[com.webauthn4j.data.PublicKeyCredentialRequestOptions]].
    *
    * @see
    *   [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-assertion]]
    *
    * @return
    *   A Play action that returns the authentication options as JSON, or an error response
    */
  def authenticationOptions: Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse("authenticationOptions", request.user, passkeyService.buildAuthenticationOptions(request.user))
  }

  /** Lists all passkeys registered for the authenticated user.
    *
    * Returns a JSON array of passkey information including ID, name, creation time, and last used time.
    *
    * @return
    *   A Play action that returns the list of passkeys as JSON, or an error response
    */
  def list: Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse("list", request.user, passkeyService.listPasskeys(request.user))
  }

  /** Deletes a passkey for the authenticated user.
    *
    * @param passkeyIdBase64
    *   The base64url-encoded passkey ID to delete
    *
    * @return
    *   A Play action that returns NoContent on success, or an error response
    */
  def delete(passkeyIdBase64: String): Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse(
      "delete",
      request.user,
      passkeyService.deletePasskey(request.user, PasskeyId.fromBase64Url(passkeyIdBase64))
    )
  }

  private def apiResponse[A](action: String, user: U, fa: => Future[A])(using
      writer: Writes[A]
  ): Future[Result] = {
    apiResponse(
      action,
      user,
      fa.map {
        case () =>
          logger.info(s"$action: ${user.id}: Success")
          NoContent
        case a =>
          logger.info(s"$action: ${user.id}: Success")
          Ok(writer.writes(a))
      }
    )
  }

  private def apiRedirectResponse[A](
      action: String,
      user: U,
      redirect: Call,
      fa: => Future[A]
  ): Future[Result] = {
    apiResponse(
      action,
      user,
      fa.map { _ =>
        logger.info(s"$action: ${user.id}: Success")
        Redirect(redirect)
      }
    )
  }

  private def apiResponse(action: String, user: U, fresult: => Future[Result]): Future[Result] =
    fresult.recover {
      case e: PasskeyException =>
        logger.warn(s"$action: ${user.id}: Domain error: ${e.getMessage}")
        BadRequest("Something went wrong")
      case e =>
        logger.error(s"$action: ${user.id}: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
}
