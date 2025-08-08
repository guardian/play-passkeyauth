package com.gu.playpasskeyauth.web

import play.api.libs.json.JsValue

trait RequestExtractor[R[_]] {
  def findUserId[A](request: R[A]): Option[String]

  def findCreationData[A](request: R[A]): Option[JsValue]

  def findAuthenticationData[A](request: R[A]): Option[JsValue]
}
