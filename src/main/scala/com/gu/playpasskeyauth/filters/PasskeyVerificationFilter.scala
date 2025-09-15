package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestWithAuthenticationData
import com.webauthn4j.data.AuthenticationData
import play.api.Logging
import play.api.mvc.Results.{BadRequest, InternalServerError}
import play.api.mvc.{ActionFilter, Result}

import scala.concurrent.{ExecutionContext, Future}

/** Verifies passkey presented in request and only allows an action to continue if verification is successful.
  *
  * See [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]].
  */
class PasskeyVerificationFilter(verifier: PasskeyVerificationService)(using
    val executionContext: ExecutionContext
) extends ActionFilter[RequestWithAuthenticationData]
    with Logging {

  def filter[A](request: RequestWithAuthenticationData[A]): Future[Option[Result]] =
    apiResponse(verifier.verify(request.user, request.authenticationData))

  private def apiResponse(auth: => Future[AuthenticationData]): Future[Option[Result]] =
    auth
      .map { _ =>
        logger.info("Verified passkey")
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
