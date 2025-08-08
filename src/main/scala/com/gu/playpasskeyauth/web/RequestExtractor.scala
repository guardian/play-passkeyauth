package com.gu.playpasskeyauth.web

import com.webauthn4j.data.AuthenticationData

trait RequestExtractor[R[_]] {
  def findUserId[A](request: R[A]): Option[String]

  def findCreationData[A](request: R[A]): Option[String]

  def findAuthenticationData[A](request: R[A]): Option[AuthenticationData]
}
