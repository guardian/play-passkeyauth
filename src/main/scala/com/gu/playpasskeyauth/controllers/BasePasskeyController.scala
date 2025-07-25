package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.utilities.Utilities.*
import com.gu.playpasskeyauth.web.RequestHelper
import play.api.Logging
import play.api.libs.json.Writes
import play.api.mvc.*
import play.api.mvc.Results.InternalServerError

import scala.concurrent.{ExecutionContext, Future}

/** Controller for handling passkey registration and verification. */
abstract class BasePasskeyController[R[_]](
    controllerComponents: ControllerComponents,
    customAction: ActionBuilder[R, AnyContent],
    passkeyService: PasskeyVerificationService
)(using reqHelper: RequestHelper[R], ec: ExecutionContext)
    extends AbstractController(controllerComponents)
    with Logging {

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair]].
    */
  def creationOptions: Action[Unit] = customAction.async(parse.empty) { request =>
    apiResponse(for {
      userId <- reqHelper
        .findUserId(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Creation options request missing user ID")))
      options <- passkeyService.creationOptions(userId)
    } yield options)
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server]].
    */
  def register: Action[AnyContent] = customAction.async { request =>
    apiResponse(for {
      userId <- reqHelper
        .findUserId(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Register request missing user ID")))
      jsonCreationResponse <- reqHelper
        .findCreationData(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Register request missing creation data")))
      _ <- passkeyService.register(userId, jsonCreationResponse)
    } yield ())
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-assertion]].
    */
  def authenticationOptions: Action[Unit] = customAction.async(parse.empty) { request =>
    apiResponse(for {
      userId <- reqHelper
        .findUserId(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Auth options request missing user ID")))
      options <- passkeyService.authenticationOptions(userId)
    } yield options)
  }

  private def apiResponse[A](fa: => Future[A])(using writer: Writes[A]): Future[Result] =
    fa
      .map {
        case () =>
          logger.info("Success")
          NoContent
        case a =>
          logger.info("Success")
          Ok(writer.writes(a))
      }
      .recover {
        case e: IllegalArgumentException =>
          logger.error(e.getMessage, e)
          BadRequest("Something went wrong")
        case e =>
          logger.error(e.getMessage, e)
          InternalServerError("Something went wrong")
      }
}
