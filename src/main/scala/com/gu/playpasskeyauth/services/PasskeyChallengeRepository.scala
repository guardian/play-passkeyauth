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
  * There should always be 0..1 challenges of each [[ChallengeType]] per user.
  *
  * @note
  *   Implementations are responsible for:
  *   - Storing challenges with their expiration timestamps
  *   - Rejecting expired challenges when loading (returning a failed Future)
  *   - Optionally cleaning up expired challenges periodically
  *
  * @example
  *   {{{
  * class MyRedisRepo extends PasskeyChallengeRepository {
  *   def load(userId: UserId, challengeType: ChallengeType): Future[Challenge] =
  *     redis.get(key(userId, challengeType)).map(deserialise)
  *
  *   def insert(userId: UserId, challenge: Challenge, expiresAt: Instant, challengeType: ChallengeType): Future[Unit] =
  *     redis.setex(key(userId, challengeType), ttl(expiresAt), serialise(challenge))
  *
  *   def delete(userId: UserId, challengeType: ChallengeType): Future[Unit] =
  *     redis.del(key(userId, challengeType))
  *
  *   private def key(userId: UserId, ct: ChallengeType) = s"challenge:${ct}:${userId.value}"
  * }
  *   }}}
  */
trait PasskeyChallengeRepository {

  /** Loads the current challenge so that it can be compared with the one offered at registration or authentication.
    * This method should only be called when a challenge is expected to be stored.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @param challengeType
    *   Whether this is a registration or authentication challenge
    * @return
    *   The challenge. Should fail if no valid (non-expired) challenge exists.
    */
  def load(userId: UserId, challengeType: ChallengeType): Future[Challenge]

  /** Inserts a challenge for the given user, replacing any existing challenge of the same type.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @param challenge
    *   Challenge to store
    * @param expiresAt
    *   When this challenge expires and should no longer be accepted
    * @param challengeType
    *   Whether this is a registration or authentication challenge
    * @return
    *   Indication of success
    */
  def insert(userId: UserId, challenge: Challenge, expiresAt: Instant, challengeType: ChallengeType): Future[Unit]

  /** Deletes the user's challenge. When this is called it's expected that there will be precisely one challenge of the
    * given type to delete.
    *
    * @param userId
    *   ID of user corresponding to challenge
    * @param challengeType
    *   Whether this is a registration or authentication challenge
    * @return
    *   Indication of success
    */
  def delete(userId: UserId, challengeType: ChallengeType): Future[Unit]
}
