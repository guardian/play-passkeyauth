package com.gu.playpasskeyauth.services

import com.webauthn4j.data.AuthenticationData

import scala.concurrent.Future

trait PasskeyVerificationService:
  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData]
