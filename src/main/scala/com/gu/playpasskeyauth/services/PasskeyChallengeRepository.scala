package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.UserId
import com.webauthn4j.data.client.challenge.Challenge

import java.time.Instant
import scala.concurrent.Future

/** The implementation of this trait determines how passkey challenges are stored on the relying party.
  *
  * These challenges are transient data and only need to be stored for a short time between a pre-registration or
  * authentication options call and the actual operation. Implementations should respect the `expiresAt` timestamp and
  * reject or clean up expired challenges.
  *
  * @note
  *   Implementations are responsible for:
  *   - Storing challenges with their expiration timestamps
  *   - Rejecting expired challenges when loading (returning a failed Future)
  *   - Optionally cleaning up expired challenges periodically
  */
trait PasskeyChallengeRepository {

  /** Loads the current registration challenge so that it can be compared with the one offered at registration. There
    * should always be 0..1 registration challenges per user. This method should only be called when a registration
    * challenge is expected to be stored.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @return
    *   The registration challenge. Should fail if no valid (non-expired) challenge exists.
    */
  def loadRegistrationChallenge(userId: UserId): Future[Challenge]

  /** Inserts a registration challenge for the given user.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @param challenge
    *   Challenge to store
    * @param expiresAt
    *   When this challenge expires and should no longer be accepted
    * @return
    *   Indication of success
    */
  def insertRegistrationChallenge(userId: UserId, challenge: Challenge, expiresAt: Instant): Future[Unit]

  /** Deletes the user's registration challenge. When this is called it's expected that there will be precisely one
    * registration challenge to delete.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @return
    *   Indication of success
    */
  def deleteRegistrationChallenge(userId: UserId): Future[Unit]

  /** Loads the current authentication challenge so that it can be compared with the one offered for authentication.
    * There should always be 0..1 authentication challenges per user. This method should only be called when an
    * authentication challenge is expected to be stored.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @return
    *   The authentication challenge. Should fail if no valid (non-expired) challenge exists.
    */
  def loadAuthenticationChallenge(userId: UserId): Future[Challenge]

  /** Inserts an authentication challenge for the given user.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @param challenge
    *   Challenge to store
    * @param expiresAt
    *   When this challenge expires and should no longer be accepted
    * @return
    *   Indication of success
    */
  def insertAuthenticationChallenge(userId: UserId, challenge: Challenge, expiresAt: Instant): Future[Unit]

  /** Deletes the user's authentication challenge. When this is called it's expected that there will be precisely one
    * authentication challenge to delete.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @return
    *   Indication of success
    */
  def deleteAuthenticationChallenge(userId: UserId): Future[Unit]
}
