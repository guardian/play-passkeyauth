package com.gu.playpasskeyauth.services

import com.webauthn4j.data.client.challenge.Challenge

import scala.concurrent.Future

/** The implementation of this trait determines how passkey challenges are stored on the relying party.
  *
  * These challenges are transient data and only need to be stored for the maximum of a few minutes' time between a
  * pre-registration or authentication options call and the actual operation.
  */
trait PasskeyChallengeRepository {

  /** Loads the current registration challenge so that it can be compared with the one offered at registration. There
    * should always be 0..1 registration challenges per user. This method should only be called when a registration
    * challenge is expected to be stored. It should fail if there isn't precisely one registration challenge for the
    * given user.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @return
    *   The registration challenge
    */
  def loadRegistrationChallenge(userId: String): Future[Challenge]

  /** Inserts a registration challenge for the given user.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @param challenge
    *   Challenge to store
    * @return
    *   Indication of success
    */
  def insertRegistrationChallenge(userId: String, challenge: Challenge): Future[Unit]

  /** Deletes the user's registration challenge. When this is called it's expected that there will be precisely one
    * registration challenge to delete.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @return
    *   Indication of success
    */
  def deleteRegistrationChallenge(userId: String): Future[Unit]

  /** Loads the current authentication challenge so that it can be compared with the one offered for authentication.
    * There should always be 0..1 authentication challenges per user. This method should only be called when an
    * authentication challenge is expected to be stored. It should fail if there isn't precisely one authentication
    * challenge for the given user.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @return
    *   The authentication challenge
    */
  def loadAuthenticationChallenge(userId: String): Future[Challenge]

  /** Inserts an authentication challenge for the given user.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @param challenge
    *   Challenge to store
    * @return
    *   Indication of success
    */
  def insertAuthenticationChallenge(userId: String, challenge: Challenge): Future[Unit]

  /** Deletes the user's authentication challenge. When this is called it's expected that there will be precisely one
    * authentication challenge to delete.
    *
    * @param userId
    *   Implementation-specific ID of user corresponding to challenge
    * @return
    *   Indication of success
    */
  def deleteAuthenticationChallenge(userId: String): Future[Unit]
}
