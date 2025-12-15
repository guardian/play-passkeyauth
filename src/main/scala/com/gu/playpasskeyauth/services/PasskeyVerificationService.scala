package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{PasskeyId, PasskeyInfo, PasskeyUser}
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
  *
  * @tparam U
  *   The user type, which must have a [[PasskeyUser]] type class instance.
  */
trait PasskeyVerificationService[U: PasskeyUser] {

  /** Builds the options needed for creating a new passkey credential in the browser.
    *
    * @param user
    *   The user for whom to generate creation options
    *
    * @return
    *   A Future containing [[com.webauthn4j.data.PublicKeyCredentialCreationOptions]] to be passed to
    *   `navigator.credentials.create()` in the browser
    */
  def buildCreationOptions(user: U): Future[PublicKeyCredentialCreationOptions]

  /** Registers a new passkey credential for the user.
    *
    * @param user
    *   The user registering the passkey
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
  def register(user: U, passkeyName: String, creationResponse: JsValue): Future[CredentialRecord]

  /** Lists all passkeys registered for the user.
    *
    * @param user
    *   The user whose passkeys to list
    *
    * @return
    *   A Future containing a list of [[PasskeyInfo]] with metadata about each passkey
    */
  def listPasskeys(user: U): Future[List[PasskeyInfo]]

  /** Deletes a passkey for the user.
    *
    * @param user
    *   The user who owns the passkey
    *
    * @param passkeyId
    *   The ID of the passkey to delete
    *
    * @return
    *   A Future that completes when the passkey is deleted
    */
  def deletePasskey(user: U, passkeyId: PasskeyId): Future[Unit]

  /** Builds the options needed for authenticating with an existing passkey.
    *
    * @param user
    *   The user attempting to authenticate
    *
    * @return
    *   A Future containing [[com.webauthn4j.data.PublicKeyCredentialRequestOptions]] to be passed to
    *   `navigator.credentials.get()` in the browser
    */
  def buildAuthenticationOptions(user: U): Future[PublicKeyCredentialRequestOptions]

  /** Verifies the given authentication response with the data stored by the relying party. Also updates the stored data
    * to keep it current. The signature counter and the last used timestamp will be updated following successful
    * verification.
    *
    * @param user
    *   The user attempting to authenticate
    *
    * @param authenticationResponse
    *   The JSON response from `navigator.credentials.get()` in the browser.
    *
    * @return
    *   A Future containing [[com.webauthn4j.data.AuthenticationData]] upon successful verification
    */
  def verify(user: U, authenticationResponse: JsValue): Future[AuthenticationData]
}
