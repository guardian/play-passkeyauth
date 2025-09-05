package com.gu.playpasskeyauth.web

import com.gu.googleauth.AuthAction.UserIdentityRequest
import com.gu.googleauth.UserIdentity
import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

// TODO: rename as it contains auth data rather than request for data
class AuthenticationDataRequest[A](
    val authenticationData: JsValue,
    request: UserIdentityRequest[A]
) extends WrappedRequest[A](request) {
  def user: UserIdentity = request.user
}

trait AuthenticationDataExtractor {
  def findAuthenticationData[A](request: UserIdentityRequest[A]): Option[JsValue]
}

class AuthenticationDataAction(extractor: AuthenticationDataExtractor)(using val executionContext: ExecutionContext)
    extends ActionRefiner[UserIdentityRequest, AuthenticationDataRequest] {

  protected def refine[A](request: UserIdentityRequest[A]): Future[Either[Result, AuthenticationDataRequest[A]]] =
    extractor.findAuthenticationData(request) match {
      case Some(jsValue) => Future.successful(Right(new AuthenticationDataRequest(jsValue, request)))
      case None          => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
