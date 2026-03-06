package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.mvc.Results.BadRequest

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries passkey creation data along with the user and original request.
  *
  * This is used during passkey registration to pass the credential creation response from the browser's WebAuthn API
  * through the request processing chain.
  *
  * @tparam U
  *   The user type
  *
  * @tparam A
  *   The body content type (e.g., `AnyContent`, `JsValue`)
  *
  * @param passkeyName
  *   A human-readable name for this passkey credential, typically provided by the user. Examples: "Mac Chrome", "Apple
  *   keychain", "Yubikey"
  *
  * @param creationData
  *   The JSON response from `navigator.credentials.create()` in the browser. This contains the public key credential
  *   data needed to register the passkey.
  *
  * @param user
  *   The authenticated user registering the passkey
  *
  * @param request
  *   The original Play request being wrapped
  */
case class RequestWithCreationData[U, A](
    passkeyName: String,
    creationData: JsValue,
    user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

private[playpasskeyauth] class CreationDataAction[U](
    findCreationData: RequestWithUser[U, ?] => Option[JsValue],
    findPasskeyName: RequestWithUser[U, ?] => Option[String]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithCreationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithCreationData[U, A]]] =
    (findPasskeyName(request), findCreationData(request)) match {
      case (Some(name), Some(jsValue)) =>
        Future.successful(Right(RequestWithCreationData(name, jsValue, request.user, request)))
      case _ => Future.successful(Left(BadRequest("Expected creation data")))
    }
}
