package controllers

import com.gu.playpasskeyauth.PasskeyAuthSimple
import com.gu.playpasskeyauth.models.{PasskeyId, UserId}
import models.User
import play.api.libs.json.{JsError, JsSuccess, JsValue, Json}
import play.api.mvc.*

import javax.inject.*
import scala.concurrent.{ExecutionContext, Future}
// The library provides JSON encoders for WebAuthn types
import com.gu.playpasskeyauth.models.JsonEncodings.given

/** Controller demonstrating passkey operations using the play-passkeyauth library.
  *
  * This controller shows the simplest possible integration using PasskeyAuthSimple. It handles:
  *   - Registration: Creating options and registering new passkeys
  *   - Authentication: Creating options and verifying passkey assertions
  *   - Management: Listing and deleting passkeys
  *
  * In a real application, you would:
  *   - Extract the user from a data store or JWT token
  *   - Add proper error handling and user feedback
  *   - Integrate with your existing authentication system
  */
@Singleton
class PasskeyController @Inject() (
    cc: ControllerComponents,
    passkeyAuth: PasskeyAuthSimple
)(implicit ec: ExecutionContext)
    extends AbstractController(cc) {

  // In a real app, you would extract the user from a token or by other means
  // For this example, we use a hardcoded demo user
  private def currentUser: User = User.demo
  private def currentUserId: UserId = UserId.from(currentUser)

  /** GET /register/options
    *
    * Creates WebAuthn credential creation options for registering a new passkey.
    *
    * Frontend should call navigator.credentials.create() with these options.
    */
  def createOptions(): Action[AnyContent] = Action.async { implicit request =>
    passkeyAuth.createOptions(currentUserId, currentUser.username).map { options =>
      Ok(Json.toJson(options))
    }
  }

  /** POST /register
    *
    * Registers a new passkey for the current user.
    *
    * Expects JSON body with:
    *   - name: String (friendly name for the passkey, e.g., "My YubiKey")
    *   - credential: Object (the response from navigator.credentials.create())
    */
  def register(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    val nameResult = (request.body \ "name").validate[String]
    val credentialResult = (request.body \ "credential").validate[JsValue]

    (nameResult, credentialResult) match {
      case (JsSuccess(name, _), JsSuccess(credential, _)) =>
        passkeyAuth
          .register(currentUserId, name, credential)
          .map { _ =>
            Ok(Json.obj("success" -> true, "message" -> "Passkey registered successfully"))
          }
          .recover { case e: Exception =>
            BadRequest(Json.obj("error" -> e.getMessage))
          }
      case _ =>
        Future.successful(BadRequest(Json.obj("error" -> "Invalid request body")))
    }
  }

  /** GET /auth/options
    *
    * Creates WebAuthn credential request options for authenticating with a passkey.
    *
    * Frontend should call navigator.credentials.get() with these options.
    */
  def authOptions(): Action[AnyContent] = Action.async { implicit request =>
    passkeyAuth.authOptions(currentUserId).map { options =>
      Ok(Json.toJson(options))
    }
  }

  /** POST /auth
    *
    * Verifies a passkey authentication attempt.
    *
    * Expects JSON body with:
    *   - assertion: Object (the response from navigator.credentials.get())
    */
  def authenticate(): Action[JsValue] = Action.async(parse.json) { implicit request =>
    val assertionResult = (request.body \ "assertion").validate[JsValue]

    assertionResult match {
      case JsSuccess(assertion, _) =>
        passkeyAuth
          .verify(currentUserId, assertion)
          .map { _ =>
            Ok(Json.obj("success" -> true, "message" -> "Authentication successful"))
          }
          .recover { case e: Exception =>
            Unauthorized(Json.obj("error" -> e.getMessage))
          }
      case JsError(_) =>
        Future.successful(BadRequest(Json.obj("error" -> "Invalid request body")))
    }
  }

  /** GET /passkeys
    *
    * Lists all passkeys registered for the current user.
    *
    * Returns JSON array of passkey metadata (not the credentials themselves).
    */
  def list(): Action[AnyContent] = Action.async { implicit request =>
    passkeyAuth.list(currentUserId).map { passkeys =>
      Ok(Json.toJson(passkeys))
    }
  }

  /** DELETE /passkeys/:id
    *
    * Deletes a passkey for the current user.
    *
    * @param id
    *   The passkey ID to delete
    */
  def delete(id: String): Action[AnyContent] = Action.async { implicit request =>
    passkeyAuth
      .delete(currentUserId, PasskeyId.fromBase64Url(id))
      .map { _ =>
        Ok(Json.obj("success" -> true, "message" -> "Passkey deleted successfully"))
      }
      .recover { case e: Exception =>
        BadRequest(Json.obj("error" -> e.getMessage))
      }
  }
}
