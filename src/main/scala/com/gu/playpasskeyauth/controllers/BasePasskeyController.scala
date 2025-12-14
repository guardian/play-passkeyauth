package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.models.PasskeyUser
import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.{RequestWithAuthenticationData, RequestWithCreationData, RequestWithUser}
import play.api.Logging
import play.api.libs.json.Writes
import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}

/** Controller for handling passkey registration and verification.
  */
class BasePasskeyController[U: PasskeyUser](
    controllerComponents: ControllerComponents,
    passkeyService: PasskeyVerificationService[U],
    userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], AnyContent],
    creationDataAction: ActionBuilder[[A] =>> RequestWithCreationData[U, A], AnyContent],
    registrationRedirect: Call
)(using val executionContext: ExecutionContext)
    extends AbstractController(controllerComponents)
    with Logging {

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair]].
    */
  def creationOptions: Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse(
      "creationOptions",
      request.user,
      passkeyService.buildCreationOptions(request.user)
    )
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server]].
    */
  def register: Action[AnyContent] = creationDataAction.async { request =>
    apiRedirectResponse(
      "register",
      request.user,
      registrationRedirect,
      passkeyService.register(request.user, request.passkeyName, request.creationData).map(_ => ())
    )
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-assertion]].
    */
  def authenticationOptions: Action[Unit] = userAction.async(parse.empty) { request =>
    apiResponse("authenticationOptions", request.user, passkeyService.buildAuthenticationOptions(request.user))
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
      case e: IllegalArgumentException =>
        logger.error(s"$action: ${user.id}: Failure: ${e.getMessage}", e)
        BadRequest("Something went wrong")
      case e =>
        logger.error(s"$action: ${user.id}: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
}
