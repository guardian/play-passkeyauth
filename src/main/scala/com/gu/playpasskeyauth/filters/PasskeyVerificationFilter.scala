package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestExtractor
import com.webauthn4j.data.AuthenticationData
import play.api.Logging
import play.api.mvc.Results.{BadRequest, InternalServerError}
import play.api.mvc.{ActionFilter, Result}

import scala.concurrent.{ExecutionContext, Future}
import com.gu.playpasskeyauth.utilities.Utilities.*

/** Verifies passkey presented in request and only allows an action to continue if verification is successful.
  *
  * See [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]].
  */
class PasskeyVerificationFilter[R[_]](verifier: PasskeyVerificationService)(using
    reqExtractor: RequestExtractor[R],
    val executionContext: ExecutionContext
) extends ActionFilter[R]
    with Logging {

  def filter[A](request: R[A]): Future[Option[Result]] =
    apiResponse(for {
      userId <- reqExtractor
        .findUserId(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Request missing user ID")))
      authData <- reqExtractor
        .findAuthenticationData(request)
        .toFutureOr(Future.failed(new IllegalArgumentException("Request missing authentication data")))
      response <- verifier.verify(userId, authData)
    } yield response)

  private def apiResponse(auth: => Future[AuthenticationData]): Future[Option[Result]] =
    auth
      .map { _ =>
        logger.info("Verified authentication data")
        None
      }
      .recover {
        case e: IllegalArgumentException =>
          logger.error(e.getMessage, e)
          Some(BadRequest("Something went wrong"))
        case e =>
          logger.error(e.getMessage, e)
          Some(InternalServerError("Something went wrong"))
      }
}
