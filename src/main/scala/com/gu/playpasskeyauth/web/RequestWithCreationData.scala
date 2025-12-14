package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

class RequestWithCreationData[U, A](
    val passkeyName: String,
    val creationData: JsValue,
    val user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** There are any number of ways to find creation data in a request so this is left to the implementer of this trait to
  * decide. This creation data is the json that's returned by a `navigator.credentials.create` call in a browser. It's
  * optional in case the request doesn't actually contain the data.
  */
trait CreationDataExtractor[R[_] <: Request[_]] {
  def findCreationData[A](request: R[A]): Option[JsValue]
}

/** This is left to the implementation to decide for maximum flexibility. This passkey name is returned from the browser
  * during the creation process. It's likely, but not necessary, that the passkey name and creation data are both held
  * in the same request. The value is optional in case the request doesn't actually contain the passkey name.
  */
trait PasskeyNameExtractor[R[_] <: Request[_]] {
  def findPasskeyName[A](request: R[A]): Option[String]
}

class CreationDataAction[U](
    creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithCreationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithCreationData[U, A]]] =
    (passkeyNameExtractor.findPasskeyName(request), creationDataExtractor.findCreationData(request)) match {
      case (Some(name), Some(jsValue)) =>
        Future.successful(
          Right(new RequestWithCreationData(name, jsValue, request.user, request))
        )
      case _ => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
