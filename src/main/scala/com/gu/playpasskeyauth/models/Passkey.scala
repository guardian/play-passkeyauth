package com.gu.playpasskeyauth.models

import com.webauthn4j.credential.CredentialRecord
import play.api.libs.json.{Json, Writes}

import java.time.{Clock, Instant}

/** Complete passkey data including metadata and credential.
  *
  * This unifies PasskeyInfo and CredentialRecord into a single model, simplifying the repository interface and making
  * it easier to work with passkey data.
  *
  * @param id
  *   The unique identifier for this passkey (credential ID)
  * @param name
  *   The user-provided friendly name for this passkey
  * @param credentialRecord
  *   The WebAuthn credential data (public key, attestation, etc.)
  * @param createdAt
  *   When the passkey was registered
  * @param lastUsedAt
  *   When the passkey was last used for authentication, if ever
  * @param signCount
  *   The signature counter from the authenticator (detects cloning)
  *
  * @example
  *   {{{
  * // Create from registration
  * val passkey = Passkey(
  *   id = PasskeyId(credentialId),
  *   name = PasskeyName.validate("My YubiKey").toOption.get,
  *   credentialRecord = credentialRecord,
  *   createdAt = Instant.now(),
  *   lastUsedAt = None,
  *   signCount = 0
  * )
  *
  * // Update after authentication
  * val updated = passkey.recordAuthentication(newCount = 1)
  *   }}}
  */
case class Passkey(
    id: PasskeyId,
    name: PasskeyName,
    credentialRecord: CredentialRecord,
    createdAt: Instant,
    lastUsedAt: Option[Instant],
    signCount: Long
) {

  /** Update this passkey after successful authentication.
    *
    * @param newCount
    *   The new signature count from the authenticator
    * @return
    *   Updated passkey with new last used time and sign count
    */
  def recordAuthentication(newCount: Long, clock: Clock): Passkey = {
    copy(lastUsedAt = Some(clock.instant()), signCount = newCount)
  }

  /** Get the metadata for this passkey (without the credential record).
    *
    * Useful for listing passkeys to users without exposing credential details.
    */
  def toInfo: PasskeyInfo = {
    PasskeyInfo(id, name, createdAt, lastUsedAt)
  }
}

object Passkey {

  /** Create a new Passkey from registration data.
    *
    * @param id
    *   The credential ID from WebAuthn
    * @param name
    *   The validated passkey name
    * @param credentialRecord
    *   The credential record from WebAuthn4J
    * @return
    *   A new Passkey with creation timestamp and zero sign count
    */
  def fromRegistration(
      id: PasskeyId,
      name: PasskeyName,
      credentialRecord: CredentialRecord,
      clock: Clock
  ): Passkey = {
    Passkey(
      id = id,
      name = name,
      credentialRecord = credentialRecord,
      createdAt = clock.instant(),
      lastUsedAt = None,
      signCount = 0
    )
  }

  /** JSON serialization for PasskeyInfo (metadata only, not credential) */
  given Writes[Passkey] = Writes { passkey =>
    Json.toJson(passkey.toInfo)
  }
}
