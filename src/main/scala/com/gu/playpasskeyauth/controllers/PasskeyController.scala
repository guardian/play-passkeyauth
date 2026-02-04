package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.models.{PasskeyId, UserIdExtractor}
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
  *   The user type for which a [[UserIdExtractor]] must be available.
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
  *   [[RequestWithUser]] containing the authenticated user.
  *
  * @param creationDataAction
  *   An action builder that extracts both the user and the passkey creation data from the request. The creation data
  *   comes from the browser's `navigator.credentials.create()` call.
  *
  * @param registrationRedirect
  *   The [[Call]] to redirect to after successful passkey registration. For example:
  *   `routes.DashboardController.index()` or `Call("GET", "/dashboard")`
  *
  * @param userIdExtractor
  *   Function to extract UserId from the user type (resolved implicitly)
  *
  * @param getUserName
  *   Function to extract display name from the user type for WebAuthn
  */
class PasskeyController[U, B](
    controllerComponents: ControllerComponents,
    passkeyService: PasskeyVerificationService,
    userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], B],
    creationDataAction: ActionBuilder[[A] =>> RequestWithCreationData[U, A], B],
    registrationRedirect: Call,
    getUserName: U => String = (u: U) => "" // Default to empty string, can be overridden
)(using userIdExtractor: UserIdExtractor[U], val executionContext: ExecutionContext)
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
    val userId = userIdExtractor(request.user)
    val userName = getUserName(request.user)
    apiResponse(
      "creationOptions",
      request.user,
      passkeyService.buildCreationOptions(userId, userName)
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
    val userId = userIdExtractor(request.user)
    apiRedirectResponse(
      "register",
      request.user,
      registrationRedirect,
      passkeyService.register(userId, request.passkeyName, request.creationData).map(_ => ())
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
    val userId = userIdExtractor(request.user)
    apiResponse("authenticationOptions", request.user, passkeyService.buildAuthenticationOptions(userId))
  }

  /** Lists all passkeys registered for the authenticated user.
    *
    * Returns a JSON array of passkey information including ID, name, creation time, and last used time.
    *
    * @return
    *   A Play action that returns the list of passkeys as JSON, or an error response
    */
  def list: Action[Unit] = userAction.async(parse.empty) { request =>
    val userId = userIdExtractor(request.user)
    apiResponse("list", request.user, passkeyService.listPasskeys(userId))
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
    val userId = userIdExtractor(request.user)
    apiResponse(
      "delete",
      request.user,
      passkeyService.deletePasskey(userId, PasskeyId.fromBase64Url(passkeyIdBase64))
    )
  }

  private def apiResponse[A](action: String, user: U, fa: => Future[A])(using
      writer: Writes[A]
  ): Future[Result] = {
    val userId = userIdExtractor(user)
    apiResponse(
      action,
      user,
      fa.map {
        case () =>
          logger.info(s"$action: $userId: Success")
          NoContent
        case a =>
          logger.info(s"$action: $userId: Success")
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
    val userId = userIdExtractor(user)
    apiResponse(
      action,
      user,
      fa.map { _ =>
        logger.info(s"$action: $userId: Success")
        Redirect(redirect)
      }
    )
  }

  private def apiResponse(action: String, user: U, fresult: => Future[Result]): Future[Result] = {
    val userId = userIdExtractor(user)
    fresult.recover {
      case e: PasskeyException =>
        logger.warn(s"$action: $userId: Domain error: ${e.getMessage}")
        BadRequest("Something went wrong")
      case e =>
        logger.error(s"$action: $userId: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }
}
