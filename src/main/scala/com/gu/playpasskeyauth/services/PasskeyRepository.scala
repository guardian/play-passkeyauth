package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{PasskeyId, PasskeyInfo, UserId}
import com.webauthn4j.credential.CredentialRecord

import java.time.Instant
import scala.concurrent.Future

/** The implementation of this trait determines how passkeys are stored on the relying party. */
trait PasskeyRepository {

  /** Loads a single credential record corresponding to a passkey. Needed to verify an authentication attempt.
    *
    * @param userId
    *   ID of user who owns the passkey
    * @param passkeyId
    *   Webauthn ID of corresponding passkey
    * @return
    *   Stored webauthn4j credential data
    */
  def loadPasskey(userId: UserId, passkeyId: PasskeyId): Future[CredentialRecord]

  /** Loads IDs of all passkeys belonging to a given user. Needed to tell browser which authenticators to allow for
    * authentication.
    *
    * @param userId
    *   ID of owning user
    * @return
    *   List of webauthn passkey IDs
    */
  def loadPasskeyIds(userId: UserId): Future[List[PasskeyId]]

  /** Loads names of all passkeys belonging to a given user. Needed to ensure a registered passkey has a unique name.
    *
    * @param userId
    *   ID of owning user
    * @return
    *   List of passkey names
    */
  def loadPasskeyNames(userId: UserId): Future[List[String]]

  /** Lists all passkeys belonging to a given user with their metadata. Useful for displaying in account settings or
    * management screens.
    *
    * @param userId
    *   ID of owning user
    * @return
    *   List of passkey information including names and timestamps
    */
  def listPasskeys(userId: UserId): Future[List[PasskeyInfo]]

  /** Stores a new credential record corresponding to a passkey after successful passkey registration. Associates the
    * credential with a user ID and friendly name.
    *
    * @param userId
    *   ID of owning user
    * @param passkeyName
    *   Friendly name to recognise passkey in browser
    * @param passkey
    *   Credential record created during registration
    * @return
    *   Indication of success
    */
  def insertPasskey(userId: UserId, passkeyName: String, passkey: CredentialRecord): Future[Unit]

  /** Deletes a passkey. Users should be able to remove passkeys they no longer use or that may have been compromised.
    *
    * @param userId
    *   ID of owning user
    * @param passkeyId
    *   Webauthn ID of passkey to delete
    * @return
    *   Indication of success. Should fail if the passkey doesn't exist or doesn't belong to the user.
    */
  def deletePasskey(userId: UserId, passkeyId: PasskeyId): Future[Unit]

  /** Updates the signature count for a credential after successful authentication. This counter helps detect cloned
    * authenticators as it should increment with each use.
    *
    * @param userId
    *   ID of owning user
    * @param passkeyId
    *   Webauthn ID of corresponding passkey
    * @param signCount
    *   New value to store
    * @return
    *   Indication of success
    */
  def updateAuthenticationCount(userId: UserId, passkeyId: PasskeyId, signCount: Long): Future[Unit]

  /** Records the timestamp when a passkey was last used for authentication. Useful for tracking activity and managing
    * unused credentials.
    *
    * @param userId
    *   ID of owning user
    * @param passkeyId
    *   Webauthn ID of corresponding passkey
    * @param timestamp
    *   Last usage time
    * @return
    *   Indication of success
    */
  def updateLastUsedTime(userId: UserId, passkeyId: PasskeyId, timestamp: Instant): Future[Unit]
}
