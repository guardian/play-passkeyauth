package com.gu.playpasskeyauth.web

import com.gu.googleauth.AuthAction.UserIdentityRequest
import com.gu.googleauth.UserIdentity
import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

// TODO: rename as it contains creation data rather than request for data
class CreationDataRequest[A](
    val creationData: JsValue,
    request: UserIdentityRequest[A]
) extends WrappedRequest[A](request) {
  def user: UserIdentity = request.user
}

trait CreationDataExtractor {
  def findCreationData[A](request: UserIdentityRequest[A]): Option[JsValue]
}

class CreationDataAction(extractor: CreationDataExtractor)(using val executionContext: ExecutionContext)
    extends ActionRefiner[UserIdentityRequest, CreationDataRequest] {

  protected def refine[A](request: UserIdentityRequest[A]): Future[Either[Result, CreationDataRequest[A]]] =
    extractor.findCreationData(request) match {
      case Some(jsValue) => Future.successful(Right(new CreationDataRequest(jsValue, request)))
      case None          => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
