package com.gu.playpasskeyauth.web

import com.gu.googleauth.AuthAction.UserIdentityRequest
import com.gu.googleauth.UserIdentity
import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

// TODO: rename as it contains creation data rather than request for data
class CreationDataRequest[A](
    val passkeyName: String,
    val creationData: JsValue,
    request: UserIdentityRequest[A]
) extends WrappedRequest[A](request) {
  def user: UserIdentity = request.user
}

trait CreationDataExtractor {
  def findCreationData[A](request: UserIdentityRequest[A]): Option[JsValue]
}

trait PasskeyNameExtractor {
  def findPasskeyName[A](request: UserIdentityRequest[A]): Option[String]
}

class CreationDataAction(creationDataExtractor: CreationDataExtractor, passkeyNameExtractor: PasskeyNameExtractor)(using
    val executionContext: ExecutionContext
) extends ActionRefiner[UserIdentityRequest, CreationDataRequest] {

  protected def refine[A](request: UserIdentityRequest[A]): Future[Either[Result, CreationDataRequest[A]]] =
    (passkeyNameExtractor.findPasskeyName(request), creationDataExtractor.findCreationData(request)) match {
      case (Some(name), Some(jsValue)) => Future.successful(Right(new CreationDataRequest(name, jsValue, request)))
      case _                           => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
