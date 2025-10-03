package com.gu.playpasskeyauth.controllers

import com.gu.googleauth.{AuthAction, UserIdentity}
import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.{
  CreationDataAction,
  CreationDataExtractor,
  PasskeyNameExtractor,
  RequestWithCreationData
}
import play.api.Logging
import play.api.libs.json.Writes
import play.api.mvc.*
import play.api.mvc.Results.InternalServerError

import scala.concurrent.{ExecutionContext, Future}

/** Controller for handling passkey registration and verification. */
class BasePasskeyController(
    controllerComponents: ControllerComponents,
    passkeyService: PasskeyVerificationService,
    authAction: AuthAction[AnyContent],
    creationDataExtractor: CreationDataExtractor,
    passkeyNameExtractor: PasskeyNameExtractor,
    registrationRedirectUrl: String
)(using val executionContext: ExecutionContext)
    extends AbstractController(controllerComponents)
    with Logging {

  private val creationDataAction = new CreationDataAction(creationDataExtractor, passkeyNameExtractor)
  private val userAndCreationDataAction = authAction.andThen(creationDataAction)

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair]].
    */
  def creationOptions: Action[Unit] = authAction.async(parse.empty) { request =>
    apiResponse(
      "creationOptions",
      request.user,
      passkeyService.buildCreationOptions(request.user)
    )
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server]].
    */
  def register: Action[AnyContent] = userAndCreationDataAction.async { request =>
    apiRedirectResponse(
      "register",
      request.user,
      registrationRedirectUrl,
      passkeyService.register(request.user, request.passkeyName, request.creationData).map(_ => ())
    )
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-assertion]].
    */
  def authenticationOptions: Action[Unit] = authAction.async(parse.empty) { request =>
    apiResponse("authenticationOptions", request.user, passkeyService.buildAuthenticationOptions(request.user))
  }

  private def apiResponse[A](action: String, user: UserIdentity, fa: => Future[A])(using
      writer: Writes[A]
  ): Future[Result] = {
    apiResponse(
      action,
      user,
      fa.map {
        case () =>
          logger.info(s"$action: ${user.username}: Success")
          NoContent
        case a =>
          logger.info(s"$action: ${user.username}: Success")
          Ok(writer.writes(a))
      }
    )
  }

  private def apiRedirectResponse[A](
      action: String,
      user: UserIdentity,
      redirectUrl: String,
      fa: => Future[A]
  ): Future[Result] = {
    apiResponse(
      action,
      user,
      fa.map { _ =>
        logger.info(s"$action: ${user.username}: Success")
        SeeOther(redirectUrl)
      }
    )
  }

  private def apiResponse(action: String, user: UserIdentity, fresult: => Future[Result]): Future[Result] =
    fresult.recover {
      case e: IllegalArgumentException =>
        logger.error(s"$action: ${user.username}: Failure: ${e.getMessage}", e)
        BadRequest("Something went wrong")
      case e =>
        logger.error(s"$action: ${user.username}: Failure: ${e.getMessage}", e)
        InternalServerError("Something went wrong")
    }
}
