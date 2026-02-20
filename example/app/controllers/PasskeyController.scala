package controllers

import com.gu.playpasskeyauth.PasskeyAuth
import models.User
import play.api.libs.json.Json
import play.api.mvc.*

import javax.inject.*
import scala.concurrent.ExecutionContext

/** Controller demonstrating passkey operations using the play-passkeyauth library.
  *
  * This controller delegates to the PasskeyAuth instance provided by dependency injection. PasskeyAuth handles:
  *   - Registration: Creating options and registering new passkeys
  *   - Authentication: Creating options and verifying passkey assertions
  *   - Management: Listing and deleting passkeys
  */
@Singleton
class PasskeyController @Inject() (
    cc: ControllerComponents,
    passkeyAuth: PasskeyAuth[User, AnyContent]
)(implicit ec: ExecutionContext)
    extends AbstractController(cc) {

  private val controller = passkeyAuth.controller()
  private val verificationAction = passkeyAuth.verificationAction()

  /** GET /register/options
    *
    * Creates WebAuthn credential creation options for registering a new passkey.
    *
    * Frontend should call navigator.credentials.create() with these options.
    */
  def creationOptions(): Action[Unit] = controller.creationOptions

  /** POST /register
    *
    * Registers a new passkey for the current user.
    *
    * Expects the credential response from navigator.credentials.create() in the request.
    */
  def register(): Action[AnyContent] = controller.register

  /** GET /auth/options
    *
    * Creates WebAuthn credential request options for authenticating with a passkey.
    *
    * Frontend should call navigator.credentials.get() with these options.
    */
  def authenticationOptions(): Action[Unit] = controller.authenticationOptions

  /** POST /auth
    *
    * Verifies a passkey authentication assertion from the browser.
    */
  def authenticate(): Action[AnyContent] = controller.authenticate

  /** DELETE /passkeys/:id
    *
    * Deletes a passkey for the current user.
    *
    * @param id
    *   The passkey ID to delete (base64url-encoded)
    */
  def delete(id: String): Action[Unit] = controller.delete(id)

  /** GET /passkeys
    *
    * Lists all passkeys for the current user.
    */
  def list(): Action[Unit] = controller.list

  /** POST /verify
    *
    * A sensitive endpoint that requires passkey verification (step-up authentication).
    *
    * This demonstrates a protected endpoint that performs passkey authentication before allowing access to sensitive
    * operations. The request must include the passkey assertion data in the body.
    *
    * Returns a JSON response with sensitive data only after successful passkey verification.
    */
  def verifySensitiveAction(): Action[AnyContent] = verificationAction.async { request =>
    // At this point, the user's passkey has been verified
    val user = request.user
    val response = Json.obj(
      "status" -> "success",
      "message" -> "Passkey verification successful!",
      "user" -> user.username,
      "userId" -> user.id,
      "sensitiveData" -> "This is sensitive information that required passkey authentication to access."
    )
    scala.concurrent.Future.successful(Ok(response))
  }
}
