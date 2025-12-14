package com.gu.playpasskeyauth.web

import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}

/** A request wrapper that carries an authenticated user along with the original request.
  *
  * This is used in the action pipeline to pass user information through the request processing chain, enabling
  * subsequent actions and controllers to access the authenticated user without re-extracting it.
  *
  * @tparam U
  *   The user type. Must have a [[com.gu.playpasskeyauth.models.PasskeyUser]] instance when used with this library.
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
  * def myAction = userAction.async { request: RequestWithUser[MyUser, AnyContent] =>
  *   val currentUser = request.user  // Access the authenticated user
  *   Future.successful(Ok(s"Hello, ${currentUser.name}"))
  * }
  *   }}}
  */
class RequestWithUser[U, A](
    val user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Type class for extracting a user from a specific request type.
  *
  * Implementations define how to obtain the user object from different request types. This abstraction allows the
  * passkey library to work with any authentication system.
  *
  * Note: When used with [[com.gu.playpasskeyauth.PasskeyAuth]], the user type `U` must have a
  * [[com.gu.playpasskeyauth.models.PasskeyUser]] type class instance in scope, as it's needed to extract the user's ID
  * for passkey operations.
  *
  * @tparam U
  *   The user type to extract. Must have a [[com.gu.playpasskeyauth.models.PasskeyUser]] instance when used with this
  *   library.
  *
  * @tparam R
  *   The request type (must be a subtype of Play's `Request`)
  *
  * @example
  *   {{{
  * import com.gu.playpasskeyauth.models.PasskeyUser
  *
  * case class MyUser(email: String, name: String)
  *
  * // First, define how to get an ID from your user type
  * given PasskeyUser[MyUser] with
  *   extension (user: MyUser) def id: String = user.email
  *
  * // Then implement the extractor for your request type
  * given UserExtractor[MyUser, AuthenticatedRequest] with {
  *   def extractUser[A](request: AuthenticatedRequest[A]): MyUser = request.user
  * }
  *   }}}
  */
trait UserExtractor[U, R[_] <: Request[_]] {
  def extractUser[A](request: R[A]): U
}

/** Action refiner that transforms a request into a [[RequestWithUser]].
  *
  * This action refiner extracts the user from the incoming request using the provided [[UserExtractor]] and wraps the
  * request in a [[RequestWithUser]] for downstream processing.
  *
  * @tparam U
  *   The user type to extract
  *
  * @tparam R
  *   The input request type (must be a subtype of Play's `Request`)
  *
  * @param userExtractor
  *   The strategy for extracting the user from the request
  */
class UserAction[U, R[A] <: Request[A]](
    userExtractor: UserExtractor[U, R]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[R, [A] =>> RequestWithUser[U, A]] {

  protected def refine[A](request: R[A]): Future[Either[Result, RequestWithUser[U, A]]] =
    Future.successful(Right(new RequestWithUser(userExtractor.extractUser(request), request)))
}
