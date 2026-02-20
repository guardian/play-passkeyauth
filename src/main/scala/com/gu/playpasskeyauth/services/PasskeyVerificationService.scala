package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{Passkey, PasskeyId, UserId}
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.JsValue

import scala.concurrent.Future

/** Service trait for passkey (WebAuthn) operations.
  *
  * Implementations handle the server-side operations required for WebAuthn credential registration and authentication.
  * This includes generating challenges, validating credentials, and storing credential data.
  *
  * The standard implementation is provided by [[PasskeyVerificationServiceImpl]].
  */
trait PasskeyVerificationService {

  /** Builds the options needed for creating a new passkey credential in the browser.
    *
    * @param userId
    *   The user ID for whom to generate creation options
    * @param userName
    *   The user's display name for WebAuthn
    *
    * @return
    *   A Future containing [[com.webauthn4j.data.PublicKeyCredentialCreationOptions]] to be passed to
    *   `navigator.credentials.create()` in the browser
    */
  def buildCreationOptions(userId: UserId, userName: String): Future[PublicKeyCredentialCreationOptions]

  /** Registers a new passkey credential for the user.
    *
    * @param userId
    *   The user ID registering the passkey
    *
    * @param passkeyName
    *   A human-readable name for this passkey
    *
    * @param creationResponse
    *   The JSON response from `navigator.credentials.create()` in the browser.
    *
    * @return
    *   A Future containing the registered [[com.webauthn4j.credential.CredentialRecord]]
    */
  def registerPasskey(userId: UserId, passkeyName: String, creationResponse: JsValue): Future[CredentialRecord]

  /** Lists all passkeys registered for the user.
    *
    * @param userId
    *   The user ID whose passkeys to list
    *
    * @return
    *   A Future containing a list of [[Passkey]] with metadata about each passkey
    */
  def listPasskeys(userId: UserId): Future[List[Passkey]]

  /** Deletes a passkey for the user.
    *
    * @param userId
    *   The user ID who owns the passkey
    *
    * @param passkeyId
    *   The ID of the passkey to delete
    *
    * @return
    *   A Future that completes when the passkey is deleted
    */
  def deletePasskey(userId: UserId, passkeyId: PasskeyId): Future[Unit]

  /** Builds the options needed for authenticating with a passkey in the browser.
    *
    * @param userId
    *   The user ID for whom to generate authentication options
    *
    * @return
    *   A Future containing [[com.webauthn4j.data.PublicKeyCredentialRequestOptions]] to be passed to
    *   `navigator.credentials.get()` in the browser
    */
  def buildAuthenticationOptions(userId: UserId): Future[PublicKeyCredentialRequestOptions]

  /** Verifies a passkey authentication attempt.
    *
    * @param userId
    *   The user ID attempting authentication
    *
    * @param authenticationResponse
    *   The JSON response from `navigator.credentials.get()` in the browser
    *
    * @return
    *   A Future containing the verified [[com.webauthn4j.data.AuthenticationData]]
    */
  def verifyPasskey(userId: UserId, authenticationResponse: JsValue): Future[AuthenticationData]
}
