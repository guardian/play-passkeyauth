package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.PasskeyAuthSimple
import com.gu.playpasskeyauth.models.{JsonEncodings, PasskeyId, UserId}
import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.services.PasskeyException
import play.api.Logging
import play.api.libs.json.{JsValue, Writes}
import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

/** Simplified controller for passkey operations.
  *
  * This controller works directly with PasskeyAuthSimple and standard Play actions. No complex action builders or
  * request wrappers required.
  *
  * @param cc
  *   Controller components
  * @param passkeyAuth
  *   The PasskeyAuthSimple instance
  * @param extractUserId
  *   Function to extract the user ID from a request (injected by client)
  * @param extractUserName
  *   Function to extract the user's display name from a request (injected by client)
  * @param registrationRedirect
  *   Where to redirect after successful registration
  *
  * @example
  *   {{{
  * // In your application
  * class MyPasskeyController @Inject()(
  *   cc: ControllerComponents,
  *   passkeyAuth: PasskeyAuthSimple,
  *   authAction: AuthenticatedAction
  * )(using ExecutionContext) extends PasskeyControllerSimple(
  *   cc,
  *   passkeyAuth,
  *   extractUserId = req => Future.successful(UserId(req.session("userId"))),
  *   extractUserName = req => Future.successful(req.session.get("userName").getOrElse("User")),
  *   registrationRedirect = routes.AccountController.settings()
  * )
  *   }}}
  */
class PasskeyControllerSimple(
    cc: ControllerComponents,
    passkeyAuth: PasskeyAuthSimple,
    extractUserId: Request[_] => Future[UserId],
    extractUserName: Request[_] => Future[String],
    registrationRedirect: Call
)(using ExecutionContext)
    extends AbstractController(cc)
    with Logging {

  /** Generate options for registering a new passkey.
    *
    * Call this before `navigator.credentials.create()` in the browser.
    */
  def creationOptions: Action[AnyContent] = Action.async { request =>
    (for {
      userId <- extractUserId(request)
      userName <- extractUserName(request)
      options <- passkeyAuth.createOptions(userId, userName)
    } yield {
      logger.info(s"creationOptions: $userId: Success")
      Ok(JsonEncodings.toPlayJson(options))
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"creationOptions: Domain error: ${e.getMessage}")
        BadRequest("Failed to build options for passkey creation because of bad data")
      case e =>
        logger.error(s"creationOptions: Failure: ${e.getMessage}", e)
        InternalServerError("Failed to build options for passkey creation because of a server error")
    }
  }

  /** Register a new passkey.
    *
    * Expects JSON body with:
    *   - name: String (friendly name for the passkey, e.g., "My YubiKey")
    *   - credential: JsValue (the response from navigator.credentials.create())
    */
  def register: Action[JsValue] = Action.async(parse.json) { request =>
    (for {
      userId <- extractUserId(request)
      name <- extractPasskeyName(request)
      credential <- extractCredential(request)
      _ <- passkeyAuth.register(userId, name, credential)
    } yield {
      logger.info(s"register: $userId: Success")
      Redirect(registrationRedirect)
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"register: Domain error: ${e.getMessage}")
        BadRequest("Registration of passkey failed")
      case e =>
        logger.error(s"register: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }

  /** Generate options for authenticating with a passkey.
    *
    * Call this before `navigator.credentials.get()` in the browser.
    */
  def authenticationOptions: Action[AnyContent] = Action.async { request =>
    (for {
      userId <- extractUserId(request)
      options <- passkeyAuth.authOptions(userId)
    } yield {
      logger.info(s"authenticationOptions: $userId: Success")
      Ok(JsonEncodings.toPlayJson(options))
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"authenticationOptions: Domain error: ${e.getMessage}")
        BadRequest("Failed to build options for passkey authentication")
      case e =>
        logger.error(s"authenticationOptions: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }

  /** Verify a passkey authentication attempt.
    *
    * Expects JSON body with:
    *   - assertion: JsValue (from navigator.credentials.get())
    */
  def verify: Action[JsValue] = Action.async(parse.json) { request =>
    (for {
      userId <- extractUserId(request)
      assertion <- extractAssertion(request)
      _ <- passkeyAuth.verify(userId, assertion)
    } yield {
      logger.info(s"verify: $userId: Success")
      Ok("Verified")
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"verify: Domain error: ${e.getMessage}")
        Unauthorized("Verification failed")
      case e =>
        logger.error(s"verify: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }

  /** List all passkeys for the authenticated user. */
  def list: Action[AnyContent] = Action.async { request =>
    (for {
      userId <- extractUserId(request)
      passkeys <- passkeyAuth.list(userId)
    } yield {
      logger.info(s"list: $userId: Success")
      Ok(JsonEncodings.toPlayJson(passkeys))
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"list: Domain error: ${e.getMessage}")
        BadRequest("Failed to list passkeys")
      case e =>
        logger.error(s"list: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }

  /** Delete a passkey.
    *
    * @param passkeyIdBase64
    *   The base64url-encoded passkey ID
    */
  def delete(passkeyIdBase64: String): Action[AnyContent] = Action.async { request =>
    (for {
      userId <- extractUserId(request)
      passkeyId = PasskeyId.fromBase64Url(passkeyIdBase64)
      _ <- passkeyAuth.delete(userId, passkeyId)
    } yield {
      logger.info(s"delete: $userId: Success")
      NoContent
    }).recover {
      case e: PasskeyException =>
        logger.warn(s"delete: Domain error: ${e.getMessage}")
        BadRequest("Failed to delete passkey")
      case e =>
        logger.error(s"delete: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
  }

  private def extractPasskeyName(request: Request[_]): Future[String] = {
    Future.fromTry(Try {
      passkeyAuth.config.requestConfig
        .extractPasskeyName(request)
        .getOrElse(throw new IllegalArgumentException("Missing passkey name in request"))
    })
  }

  private def extractCredential(request: Request[_]): Future[JsValue] = {
    Future.fromTry(Try {
      passkeyAuth.config.requestConfig
        .extractCredential(request)
        .getOrElse(throw new IllegalArgumentException("Missing credential in request"))
    })
  }

  private def extractAssertion(request: Request[_]): Future[JsValue] = {
    Future.fromTry(Try {
      passkeyAuth.config.requestConfig
        .extractAssertion(request)
        .getOrElse(throw new IllegalArgumentException("Missing assertion in request"))
    })
  }
}
