package com.gu.playpasskeyauth.services

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}

import scala.concurrent.Future

trait PasskeyVerificationService {

  def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions]

  def register(userId: String, jsonCreationResponse: String): Future[CredentialRecord]

  def authenticationOptions(userId: String): Future[PublicKeyCredentialRequestOptions]

  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData]
}
