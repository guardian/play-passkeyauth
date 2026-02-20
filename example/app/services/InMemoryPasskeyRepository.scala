package services

import com.gu.playpasskeyauth.models.{Passkey, PasskeyId, UserId}
import com.gu.playpasskeyauth.services.PasskeyRepository

import javax.inject.Singleton
import scala.collection.concurrent.TrieMap
import scala.concurrent.Future

/** In-memory implementation of PasskeyRepository for the example application.
  *
  * This stores passkeys in a concurrent map. In a real application, you would use a database like PostgreSQL, MongoDB,
  * DynamoDB, etc.
  *
  * The key is a tuple of (UserId, PasskeyId) to ensure each user's passkeys are properly isolated.
  */
@Singleton
class InMemoryPasskeyRepository extends PasskeyRepository {

  private val passkeys = TrieMap.empty[(String, String), Passkey]

  override def get(userId: UserId, passkeyId: PasskeyId): Future[Passkey] = {
    passkeys.get((userId.value, passkeyId.toBase64Url)) match {
      case Some(passkey) => Future.successful(passkey)
      case None          =>
        Future.failed(
          new NoSuchElementException(s"Passkey not found: userId=${userId.value}, passkeyId=${passkeyId.toBase64Url}")
        )
    }
  }

  override def list(userId: UserId): Future[List[Passkey]] = {
    val userPasskeys = passkeys.collect {
      case ((uid, _), passkey) if uid == userId.value => passkey
    }.toList
    Future.successful(userPasskeys)
  }

  override def upsert(userId: UserId, passkey: Passkey): Future[Unit] = {
    passkeys.put((userId.value, passkey.id.toBase64Url), passkey)
    Future.successful(())
  }

  override def delete(userId: UserId, passkeyId: PasskeyId): Future[Unit] = {
    passkeys.remove((userId.value, passkeyId.toBase64Url))
    Future.successful(())
  }
}
