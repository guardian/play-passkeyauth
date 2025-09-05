package com.gu.playpasskeyauth.services

import com.gu.googleauth.UserIdentity
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.JsValue

import scala.concurrent.Future

trait PasskeyVerificationService {

  def creationOptions(user: UserIdentity): Future[PublicKeyCredentialCreationOptions]

  def register(user: UserIdentity, creationResponse: JsValue): Future[CredentialRecord]

  def authenticationOptions(user: UserIdentity): Future[PublicKeyCredentialRequestOptions]

  def verify(user: UserIdentity, authenticationResponse: JsValue): Future[AuthenticationData]
}
