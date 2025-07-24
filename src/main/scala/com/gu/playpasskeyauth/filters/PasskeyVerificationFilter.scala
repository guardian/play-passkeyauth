package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.webauthn4j.data.AuthenticationData
import play.api.Logging
import play.api.mvc.Results.{InternalServerError, Ok, Status}
import play.api.mvc.{ActionFilter, Result}

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Success, Try}

/** Verifies passkey presented in request and only allows an action to continue if verification is successful.
  *
  * See [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]].
  */
class PasskeyVerificationFilter[R[_]](using
    requestHelper: RequestHelper[R],
    passkeyVerifier: PasskeyVerificationService,
    val executionContext: ExecutionContext
) extends ActionFilter[R]
    with Logging {

  def filter[A](request: R[A]): Future[Option[Result]] =
    apiResponse(passkeyVerifier.verify(requestHelper.findUserId(request), requestHelper.findPasskey(request)))

  private def apiResponse(auth: => Future[AuthenticationData]): Future[Option[Result]] =
    auth
      .map { _ =>
        logger.info("Verified authentication data")
        None
      }
      .recover { e =>
        logger.error(e.getMessage, e)
        Some(InternalServerError("Something went wrong"))
      }
}
