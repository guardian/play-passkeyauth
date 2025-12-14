package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.PasskeyUser
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.JsValue

import scala.concurrent.Future

trait PasskeyVerificationService[U: PasskeyUser] {

  def buildCreationOptions(user: U): Future[PublicKeyCredentialCreationOptions]

  def register(user: U, passkeyName: String, creationResponse: JsValue): Future[CredentialRecord]

  def buildAuthenticationOptions(user: U): Future[PublicKeyCredentialRequestOptions]

  /** Verifies the given authentication response with the data stored by the relying party. Also updates the stored data
    * to keep it current. The signature counter and the last used timestamp will be updated following successful
    * verification.
    */
  def verify(user: U, authenticationResponse: JsValue): Future[AuthenticationData]
}
