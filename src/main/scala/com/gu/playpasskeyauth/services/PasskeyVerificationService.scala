package com.gu.playpasskeyauth.services

import com.gu.googleauth.UserIdentity
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.JsValue

import scala.concurrent.Future

trait PasskeyVerificationService {

  def buildCreationOptions(user: UserIdentity): Future[PublicKeyCredentialCreationOptions]

  def register(user: UserIdentity, passkeyName: String, creationResponse: JsValue): Future[CredentialRecord]

  def buildAuthenticationOptions(user: UserIdentity): Future[PublicKeyCredentialRequestOptions]

  def verify(user: UserIdentity, authenticationResponse: JsValue): Future[AuthenticationData]
}
