package services

import com.gu.playpasskeyauth.models.UserId
import com.gu.playpasskeyauth.services.{ChallengeType, PasskeyChallengeRepository}
import com.webauthn4j.data.client.challenge.Challenge

import javax.inject.Singleton
import java.time.Instant
import scala.collection.concurrent.TrieMap
import scala.concurrent.Future

/** In-memory implementation of PasskeyChallengeRepository for the example application.
  *
  * This stores challenges in a concurrent map keyed by user ID and challenge type. In a real application, you would use
  * a cache like Redis, Memcached, or a database with TTL support.
  *
  * Challenges are short-lived and only need to exist between creating options and verifying credentials.
  */
@Singleton
class InMemoryChallengeRepository extends PasskeyChallengeRepository {

  private case class StoredChallenge(challenge: Challenge, expiresAt: Instant)

  private val challenges = TrieMap.empty[(String, ChallengeType), StoredChallenge]

  override def load(userId: UserId, challengeType: ChallengeType): Future[Challenge] = {
    challenges.get((userId.value, challengeType)) match {
      case Some(stored) if stored.expiresAt.isAfter(Instant.now()) =>
        Future.successful(stored.challenge)
      case Some(_) =>
        challenges.remove((userId.value, challengeType))
        Future.failed(new IllegalStateException(s"Challenge expired for user ${userId.value}"))
      case None =>
        Future.failed(new NoSuchElementException(s"No challenge found for user ${userId.value}"))
    }
  }

  override def insert(
      userId: UserId,
      challenge: Challenge,
      expiresAt: Instant,
      challengeType: ChallengeType
  ): Future[Unit] = {
    challenges.put((userId.value, challengeType), StoredChallenge(challenge, expiresAt))
    Future.successful(())
  }

  override def delete(userId: UserId, challengeType: ChallengeType): Future[Unit] = {
    challenges.remove((userId.value, challengeType))
    Future.successful(())
  }
}
