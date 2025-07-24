package com.gu.playpasskeyauth.services

import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}

import scala.concurrent.Future

trait PasskeyVerificationService {

  def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions]

  def authenticationOptions(userId: String): Future[PublicKeyCredentialRequestOptions]

  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData]
}
