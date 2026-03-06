package com.gu.playpasskeyauth.web

import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries an authenticated user along with the original request.
  *
  * This is used in the action pipeline to pass user information through the request processing chain, enabling
  * subsequent actions and controllers to access the authenticated user without re-extracting it.
  *
  * @tparam A
  *   The body content type (e.g., `AnyContent`, `JsValue`)
  *
  * @param user
  *   The authenticated user extracted from the request
  *
  * @param request
  *   The original Play request being wrapped
  *
  * @example
  *   {{{
  * // In an action:
  * def myAction = passkeyAuth.verificationAction().async { request: RequestWithUser[MyUser, AnyContent] =>
  *   val currentUser = request.user  // Access the authenticated user
  *   Future.successful(Ok(s"Hello, ${currentUser.displayName}"))
  * }
  *   }}}
  */
case class RequestWithUser[U, A](
    user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Action refiner that transforms a plain [[Request]] into a [[RequestWithUser]] by applying a user extraction
  * function.
  *
  * This is used internally by the library; consumers simply supply a `Request[?] => U` function to
  * [[com.gu.playpasskeyauth.PasskeyAuthContext]].
  *
  * @tparam U
  *   The user type to extract
  *
  * @param extractUser
  *   A function that extracts the user from any request
  */
private[playpasskeyauth] class UserAction[U](
    extractUser: Request[?] => U
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[Request, [A] =>> RequestWithUser[U, A]] {

  protected def refine[A](request: Request[A]): Future[Either[Result, RequestWithUser[U, A]]] =
    Future.successful(Right(RequestWithUser(extractUser(request), request)))
}
