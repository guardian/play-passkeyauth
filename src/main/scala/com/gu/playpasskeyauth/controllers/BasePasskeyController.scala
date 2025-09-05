package com.gu.playpasskeyauth.controllers

import com.gu.googleauth.AuthAction
import com.gu.playpasskeyauth.models.JsonEncodings.given
import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.{AuthenticationDataAction, CreationDataRequest}
import play.api.Logging
import play.api.libs.json.Writes
import play.api.mvc.*
import play.api.mvc.Results.InternalServerError

import scala.concurrent.{ExecutionContext, Future}

/** Controller for handling passkey registration and verification. */
abstract class BasePasskeyController(
    controllerComponents: ControllerComponents,
    authAction: AuthAction[AnyContent],
    userAndCreationDataAction: ActionBuilder[CreationDataRequest, AnyContent],
    passkeyService: PasskeyVerificationService
)(using val executionContext: ExecutionContext)
    extends AbstractController(controllerComponents)
    with Logging {

  // TODO remove
//  private val creationDataAction = new CreationDataAction(???)
//  private val userAndCreationDataAction = authAction.andThen(creationDataAction)

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair]].
    */
  def creationOptions: Action[Unit] = authAction.async(parse.empty) { request =>
    apiResponse(passkeyService.creationOptions(request.user))
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server]].
    */
  def register: Action[AnyContent] = userAndCreationDataAction.async { request =>
    apiResponse(passkeyService.register(request.user, request.creationData).map(_ => ()))
  }

  /** See [[https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-assertion]].
    */
  def authenticationOptions: Action[Unit] = authAction.async(parse.empty) { request =>
    apiResponse(passkeyService.authenticationOptions(request.user))
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
