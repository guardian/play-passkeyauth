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

/** Extracts passkey authentication data from a [[RequestWithUser]].
  *
  * ==Type-safety note==
  * `ActionRefiner` requires a polymorphic `refine[A]`, but the extractor needs a concrete `Request[B]`. We bridge this
  * with a single `asInstanceOf[RequestWithUser[U, B]]` cast. This is safe because:
  *   1. On the JVM, `RequestWithUser[U, A]` and `RequestWithUser[U, B]` erase to the same type — the cast never fails
  *      at runtime regardless of what `A` is.
  *   2. `AuthenticationDataAction[U, B]` is `private[playpasskeyauth]` — it is only ever constructed inside
  *      [[com.gu.playpasskeyauth.PasskeyAuth]], which holds the same `B` in scope.
  *   3. It is only ever composed via `andThen` onto an `ActionBuilder[Request, B]`, so the Play framework guarantees
  *      the actual runtime body is of type `B` for every call to `refine`.
  *   4. The cast is used only to satisfy the extractor's `Request[B]` parameter; all further work (building the result)
  *      uses the original uncast `request`.
  */
private[playpasskeyauth] class AuthenticationDataAction[U, B](
    findAuthenticationData: Request[B] => Option[JsValue]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[[A] =>> RequestWithUser[U, A], [A] =>> RequestWithAuthenticationData[U, A]] {

  protected def refine[A](
      request: RequestWithUser[U, A]
  ): Future[Either[Result, RequestWithAuthenticationData[U, A]]] = {
    // Safe: see class scaladoc. The cast is purely a type-level bridge; the object is unchanged.
    val typedRequest = request.asInstanceOf[RequestWithUser[U, B]]
    findAuthenticationData(typedRequest) match {
      case Some(jsValue) =>
        Future.successful(Right(RequestWithAuthenticationData(jsValue, request.user, request)))
      case None => Future.successful(Left(BadRequest("Expected authentication data")))
    }
  }
}
