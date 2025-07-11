package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.{PasskeyAuthFailure, PasskeyAuthService}
import com.webauthn4j.data.AuthenticationData
import play.api.Logging
import play.api.mvc.Results.{InternalServerError, Ok, Status}
import play.api.mvc.{ActionFilter, Result}

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Success, Try}

/** Performs passkey authentication and only allows an action to continue if authentication is successful.
  *
  * See [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]].
  */
class PasskeyAuthFilter[R[_]](using
    requestHelper: RequestHelper[R],
    passkeyAuth: PasskeyAuthService,
    val executionContext: ExecutionContext
) extends ActionFilter[R]
    with Logging {

  def filter[A](request: R[A]): Future[Option[Result]] =
    Future(apiResponse(passkeyAuth.verify(requestHelper.findUserId(request), requestHelper.findPasskey(request))))

  private def apiResponse(auth: => Either[PasskeyAuthFailure, AuthenticationData]): Option[Result] =
    auth match {
      case Left(fail) =>
        logger.error(fail.message)
        Some(InternalServerError("Something went wrong"))
      case Right(authData) =>
        logger.info("Verified authentication data")
        None
    }
}
