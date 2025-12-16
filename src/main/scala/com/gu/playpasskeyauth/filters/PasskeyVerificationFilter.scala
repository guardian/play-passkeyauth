package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.models.PasskeyUser
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
  *   The user type, which must have a [[PasskeyUser]] type class instance.
  *
  * @param verifier
  *   The service that performs passkey verification
  *
  * @see
  *   [[https://webauthn4j.github.io/webauthn4j/en/#webauthn-assertion-verification-and-post-processing]]
  */
class PasskeyVerificationFilter[U: PasskeyUser](verifier: PasskeyVerificationService[U])(using
    val executionContext: ExecutionContext
) extends ActionFilter[[A] =>> RequestWithAuthenticationData[U, A]]
    with Logging {

  def filter[A](request: RequestWithAuthenticationData[U, A]): Future[Option[Result]] = {
    val userId = request.user.id.value
    verifier
      .verify(request.user, request.authenticationData)
      .map { _ =>
        logger.info(s"verify: $userId: Verified passkey")
        None
      }
      .recover {
        case e: PasskeyException =>
          logger.warn(s"verify: $userId: Domain error: ${e.getMessage}")
          Some(BadRequest("Something went wrong"))
        case e =>
          logger.error(s"verify: $userId: Failure: ${e.getMessage}", e)
          Some(InternalServerError("Something went wrong"))
      }
  }
}
