package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.model.{HostApp, PasskeyMetadata}
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions}

import scala.concurrent.Future

trait PasskeyVerificationService {

  def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions]

  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData]
}
