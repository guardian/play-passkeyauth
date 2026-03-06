package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries passkey authentication data along with the user and original request.
  *
  * This is used during passkey authentication to pass the credential assertion response from the browser's WebAuthn API
  * through the request processing chain.
  *
  * @tparam U
  *   The user type
  *
  * @tparam A
  *   The body content type (e.g., `AnyContent`, `JsValue`)
  *
  * @param authenticationData
  *   The JSON response from `navigator.credentials.get()` in the browser. This contains the signed assertion data
  *   needed to verify the passkey.
  *
  * @param user
  *   The user attempting to authenticate
  *
  * @param request
  *   The original Play request being wrapped
  */
case class RequestWithAuthenticationData[U, A](
    authenticationData: JsValue,
    user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

private[playpasskeyauth] class AuthenticationDataAction[U, B](
    findAuthenticationData: Request[B] => Option[JsValue]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithAuthenticationData[U, A]] {

  protected def refine[A](
      request: RequestWithUser[U, A]
  ): Future[Either[Result, RequestWithAuthenticationData[U, A]]] = {
    val typedRequest = request.asInstanceOf[RequestWithUser[U, B]]
    findAuthenticationData(typedRequest) match {
      case Some(jsValue) =>
        Future.successful(Right(RequestWithAuthenticationData(jsValue, request.user, request)))
      case None => Future.successful(Left(BadRequest("Expected authentication data")))
    }
  }
}
