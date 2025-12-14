package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

class RequestWithAuthenticationData[U, A](
    val authenticationData: JsValue,
    val user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** There are any number of ways to find authentication data in a request so this is left to the implementer of this
  * trait to decide. This authentication data is the json that's returned by a `navigator.credentials.get` call in a
  * browser. It's optional in case the request doesn't actually contain the data.
  */
trait AuthenticationDataExtractor[R[_] <: Request[_]] {
  def findAuthenticationData[A](request: R[A]): Option[JsValue]
}

class AuthenticationDataAction[U](
    authDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithAuthenticationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithAuthenticationData[U, A]]] =
    authDataExtractor.findAuthenticationData(request) match {
      case Some(jsValue) =>
        Future.successful(
          Right(new RequestWithAuthenticationData(jsValue, request.user, request))
        )
      case None => Future.successful(Left(BadRequest("Expected authentication data")))
    }
}
