package services

import com.gu.playpasskeyauth.models.UserId
import com.gu.playpasskeyauth.services.PasskeyChallengeRepository
import com.webauthn4j.data.client.challenge.Challenge

import javax.inject.Singleton
import java.time.Instant
import scala.collection.concurrent.TrieMap
import scala.concurrent.Future

/** In-memory implementation of PasskeyChallengeRepository for the example application.
  *
  * This stores challenges in concurrent maps. In a real application, you would use a cache like Redis, Memcached, or a
  * database with TTL support.
  *
  * Challenges are short-lived and only need to exist between creating options and verifying credentials.
  */
@Singleton
class InMemoryChallengeRepository extends PasskeyChallengeRepository {

  private case class StoredChallenge(challenge: Challenge, expiresAt: Instant)

  private val registrationChallenges = TrieMap.empty[String, StoredChallenge]
  private val authenticationChallenges = TrieMap.empty[String, StoredChallenge]

  override def loadRegistrationChallenge(userId: UserId): Future[Challenge] = {
    loadChallenge(userId, registrationChallenges)
  }

  override def insertRegistrationChallenge(userId: UserId, challenge: Challenge, expiresAt: Instant): Future[Unit] = {
    insertChallenge(userId, challenge, expiresAt, registrationChallenges)
  }

  override def deleteRegistrationChallenge(userId: UserId): Future[Unit] = {
    deleteChallenge(userId, registrationChallenges)
  }

  override def loadAuthenticationChallenge(userId: UserId): Future[Challenge] = {
    loadChallenge(userId, authenticationChallenges)
  }

  override def insertAuthenticationChallenge(
      userId: UserId,
      challenge: Challenge,
      expiresAt: Instant
  ): Future[Unit] = {
    insertChallenge(userId, challenge, expiresAt, authenticationChallenges)
  }

  override def deleteAuthenticationChallenge(userId: UserId): Future[Unit] = {
    deleteChallenge(userId, authenticationChallenges)
  }

  private def loadChallenge(userId: UserId, challenges: TrieMap[String, StoredChallenge]): Future[Challenge] = {
    challenges.get(userId.value) match {
      case Some(stored) if stored.expiresAt.isAfter(Instant.now()) =>
        Future.successful(stored.challenge)
      case Some(_) =>
        // Challenge expired, remove it
        challenges.remove(userId.value)
        Future.failed(new IllegalStateException(s"Challenge expired for user ${userId.value}"))
      case None =>
        Future.failed(new NoSuchElementException(s"No challenge found for user ${userId.value}"))
    }
  }

  private def insertChallenge(
      userId: UserId,
      challenge: Challenge,
      expiresAt: Instant,
      challenges: TrieMap[String, StoredChallenge]
  ): Future[Unit] = {
    challenges.put(userId.value, StoredChallenge(challenge, expiresAt))
    Future.successful(())
  }

  private def deleteChallenge(userId: UserId, challenges: TrieMap[String, StoredChallenge]): Future[Unit] = {
    challenges.remove(userId.value)
    Future.successful(())
  }
}
