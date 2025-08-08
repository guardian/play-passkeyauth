package com.gu.playpasskeyauth.services

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.{JsObject, JsValue}

import scala.concurrent.Future

trait PasskeyVerificationService {

  def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions]

  def register(userId: String, creationResponse: JsValue): Future[CredentialRecord]

  def authenticationOptions(userId: String): Future[PublicKeyCredentialRequestOptions]

  def verify(userId: String, authenticationResponse: JsValue): Future[AuthenticationData]
}
