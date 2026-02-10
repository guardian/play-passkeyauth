package controllers

import com.gu.playpasskeyauth.PasskeyAuth
import models.User
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

  /** DELETE /passkeys/:id
    *
    * Deletes a passkey for the current user.
    *
    * @param id
    *   The passkey ID to delete (base64url-encoded)
    */
  def delete(id: String): Action[Unit] = controller.delete(id)
}
