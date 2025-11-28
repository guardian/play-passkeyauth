package com.gu.playpasskeyauth.web

import com.gu.googleauth.AuthAction.UserIdentityRequest
import com.gu.googleauth.UserIdentity
import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

class RequestWithCreationData[A](
    val passkeyName: String,
    val creationData: JsValue,
    request: UserIdentityRequest[A]
) extends WrappedRequest[A](request) {
  def user: UserIdentity = request.user
}

/** There are any number of ways to find creation data in a request so this is left to the implementer of this trait to
  * decide. This creation data is the json that's returned by a `navigator.credentials.create` call in a browser. It's
  * optional in case the request doesn't actually contain the data.
  */
trait CreationDataExtractor {
  def findCreationData[A](request: UserIdentityRequest[A]): Option[JsValue]
}

/** This is left to the implementation to decide for maximum flexibility. This passkey name is returned from the browser
  * during the creation process. It's likely, but not necessary, that the passkey name and creation data are both held
  * in the same request. The value is optional in case the request doesn't actually contain the passkey name.
  */
trait PasskeyNameExtractor {
  def findPasskeyName[A](request: UserIdentityRequest[A]): Option[String]
}

class CreationDataAction(creationDataExtractor: CreationDataExtractor, passkeyNameExtractor: PasskeyNameExtractor)(using
    val executionContext: ExecutionContext
) extends ActionRefiner[UserIdentityRequest, RequestWithCreationData] {

  protected def refine[A](request: UserIdentityRequest[A]): Future[Either[Result, RequestWithCreationData[A]]] =
    (passkeyNameExtractor.findPasskeyName(request), creationDataExtractor.findCreationData(request)) match {
      case (Some(name), Some(jsValue)) => Future.successful(Right(new RequestWithCreationData(name, jsValue, request)))
      case _                           => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
