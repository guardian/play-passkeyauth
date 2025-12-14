package com.gu.playpasskeyauth.web

import play.api.mvc.*

import scala.concurrent.{ExecutionContext, Future}

/** A request that includes an extracted user.
  */
class RequestWithUser[U, A](
    val user: U,
    request: Request[A]
) extends WrappedRequest[A](request)

/** Extracts the user from a request type.
  */
trait UserExtractor[U, R[_] <: Request[_]] {
  def extractUser[A](request: R[A]): U
}

/** Action refiner that extracts a user from the request.
  */
class UserAction[U, R[A] <: Request[A]](
    userExtractor: UserExtractor[U, R]
)(using val executionContext: ExecutionContext)
    extends ActionRefiner[R, [A] =>> RequestWithUser[U, A]] {

  protected def refine[A](request: R[A]): Future[Either[Result, RequestWithUser[U, A]]] =
    Future.successful(Right(new RequestWithUser(userExtractor.extractUser(request), request)))
}
