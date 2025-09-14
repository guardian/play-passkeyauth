package com.gu.playpasskeyauth.utilities

import scala.concurrent.Future

object Utilities {
  // TODO: remove
  extension [A](option: Option[A])
    def toFutureOr[B >: A](fallback: => Future[B]): Future[B] =
      option match
        case Some(a) => Future.successful(a)
        case None    => fallback
}
