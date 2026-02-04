package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.models.UserIdExtractor
import com.gu.playpasskeyauth.services.{PasskeyException, PasskeyVerificationService}
import com.gu.playpasskeyauth.web.RequestWithAuthenticationData
import com.webauthn4j.data.AuthenticationData
import play.api.Logging
import play.api.mvc.Results.{BadRequest, InternalServerError}
import play.api.mvc.{ActionFilter, Result}

import scala.concurrent.{ExecutionContext, Future}

/** Action filter that verifies a passkey assertion before allowing the request to proceed.
  *
  * This filter intercepts requests containing WebAuthn authentication data and verifies the passkey signature against
  * the stored credential. Only requests with valid passkey assertions are allowed through; invalid or missing
  * assertions result in error responses.
  *
  * The filter also updates the stored credential metadata (signature counter, last used timestamp) after successful
  * verification to maintain security and provide audit information.
  *
  * @tparam U
  *   The user type for which a [[UserIdExtractor]] must be available.
  *
  * @param verifier
  *   The service that performs passkey verification
  *
  * @param userIdExtractor
  *   Function to extract UserId from the user type (resolved implicitly)
  *
  * @see
  *   [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]]
  */
class PasskeyVerificationFilter[U](verifier: PasskeyVerificationService)(using
    userIdExtractor: UserIdExtractor[U],
    val executionContext: ExecutionContext
) extends ActionFilter[[A] =>> RequestWithAuthenticationData[U, A]]
    with Logging {

  def filter[A](request: RequestWithAuthenticationData[U, A]): Future[Option[Result]] = {
    val userId = userIdExtractor(request.user)
    verifier
      .verify(userId, request.authenticationData)
      .map { _ =>
        logger.info(s"verify: ${userId.value}: Verified passkey")
        None
      }
      .recover {
        case e: PasskeyException =>
          logger.warn(s"verify: ${userId.value}: Domain error: ${e.getMessage}")
          Some(BadRequest("Something went wrong"))
        case e =>
          logger.error(s"verify: ${userId.value}: Failure: ${e.getMessage}", e)
          Some(InternalServerError("Something went wrong"))
      }
  }
}
