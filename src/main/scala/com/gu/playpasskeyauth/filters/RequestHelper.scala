package com.gu.playpasskeyauth.filters

import com.webauthn4j.data.AuthenticationData

trait RequestHelper[R[_]]:
  def findUserId[A](request: R[A]): String
  def findPasskey[A](request: R[A]): AuthenticationData
