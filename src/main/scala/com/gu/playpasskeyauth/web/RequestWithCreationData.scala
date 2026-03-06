package com.gu.playpasskeyauth.web

import com.gu.playpasskeyauth.models.PasskeyName
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
  *   The validated passkey name for this credential, provided by the user. Examples: "Mac Chrome", "Apple keychain",
  *   "Yubikey"
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
    passkeyName: PasskeyName,
    creationData: JsValue,
    user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Extracts passkey creation data from a [[RequestWithUser]] and validates the passkey name.
  *
  * ==Type-safety note==
  * `ActionRefiner` requires a polymorphic `refine[A]`, but the extractors need a concrete `Request[B]`. We bridge this
  * with a single `asInstanceOf[RequestWithUser[U, B]]` cast. This is safe because:
  *   1. On the JVM, `RequestWithUser[U, A]` and `RequestWithUser[U, B]` erase to the same type — the cast never fails
  *      at runtime regardless of what `A` is.
  *   2. `CreationDataAction[U, B]` is `private[playpasskeyauth]` — it is only ever constructed inside
  *      [[com.gu.playpasskeyauth.controllers.PasskeyController]], which holds the same `B` in scope.
  *   3. It is only ever composed via `andThen` onto an `ActionBuilder[Request, B]`, so the Play framework guarantees
  *      the actual runtime body is of type `B` for every call to `refine`.
  *   4. The cast is used only to satisfy the extractor's `Request[B]` parameter; all further work (building the result)
  *      uses the original uncast `request`.
  */
private[playpasskeyauth] class CreationDataAction[U, B](
    findCreationData: Request[B] => Option[JsValue],
    findPasskeyName: Request[B] => Option[String]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithCreationData[U, A]] {

  protected def refine[A](request: RequestWithUser[U, A]): Future[Either[Result, RequestWithCreationData[U, A]]] = {
    // Safe: see class scaladoc. The cast is purely a type-level bridge; the object is unchanged.
    val typedRequest = request.asInstanceOf[RequestWithUser[U, B]]
    (findPasskeyName(typedRequest), findCreationData(typedRequest)) match {
      case (Some(rawName), Some(jsValue)) =>
        PasskeyName.validate(rawName) match {
          case Right(name) =>
            Future.successful(Right(RequestWithCreationData(name, jsValue, request.user, request)))
          case Left(error) =>
            Future.successful(Left(BadRequest(s"Invalid passkey name: ${error.message}")))
        }
      case _ => Future.successful(Left(BadRequest("Expected creation data")))
    }
  }
}
