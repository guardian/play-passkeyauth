package com.gu.playpasskeyauth.services

import com.webauthn4j.credential.CredentialRecord

import java.time.Instant
import scala.concurrent.Future

/** The implementation of this trait determines how passkeys are stored on the relying party.
  */
trait PasskeyRepository {

  /** Loads a single credential record corresponding to a passkey. Needed to verify an authentication attempt.
    *
    * @param userId
    *   Implementation-specific ID of user who owns the passkey
    * @param passkeyId
    *   Webauthn ID of corresponding passkey
    * @return
    *   Stored webauthn4j credential data
    */
  def loadPasskey(userId: String, passkeyId: Array[Byte]): Future[CredentialRecord]

  /** Loads IDs of all passkeys belonging to a given user. Needed to tell browser which authenticators to allow for
    * authentication.
    *
    * @param userId
    *   Implementation-specificID of owning user
    * @return
    *   List of webauthn passkey IDs
    */
  def loadPasskeyIds(userId: String): Future[List[String]]

  /** Stores a new credential record corresponding to a passkey after successful passkey registration. Associates the
    * credential with a user ID and friendly name.
    *
    * @param userId
    *   Implementation-specific ID of owning user
    * @param passkeyName
    *   Friendly name to recognise passkey in browser
    * @param passkey
    *   Credential record created during registration
    * @return
    *   Indication of success
    */
  def insertPasskey(userId: String, passkeyName: String, passkey: CredentialRecord): Future[Unit]

  /** Updates the signature count for a credential after successful authentication. This counter helps detect cloned
    * authenticators as it should increment with each use.
    *
    * @param userId
    *   Implementation-specific ID of owning user
    * @param signCount
    *   New value to store
    * @return
    *   Indication of success
    */
  def updateAuthenticationCount(userId: String, signCount: Long): Future[Unit]

  /** Records the timestamp when a passkey was last used for authentication. Useful for tracking activity and managing
    * unused credentials.
    *
    * @param userId
    *   Implementation-specific ID of owning user
    * @param passkeyId
    *   Webauthn ID of corresponding passkey
    * @param timestamp
    *   Last usage time
    * @return
    *   Indication of success
    */
  def updateLastUsedTime(userId: String, passkeyId: Array[Byte], timestamp: Instant): Future[Unit]
}
