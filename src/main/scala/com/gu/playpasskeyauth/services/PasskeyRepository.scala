package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{Passkey, PasskeyId, UserId}
import scala.concurrent.Future

/** Repository for storing and retrieving passkey credentials.
  *
  * This simplified interface provides 4 core CRUD operations for managing passkeys. Implementations handle the storage
  * backend (database, in-memory, etc.).
  *
  * The interface is designed to be simple and follow standard repository patterns. All passkeys are owned by a user,
  * and operations require both the user ID and passkey ID for security.
  *
  * @example
  *   {{{
  * // Create a repository implementation
  * class MyPasskeyRepository extends PasskeyRepository {
  *   def get(userId: UserId, passkeyId: PasskeyId): Future[Passkey] = {
  *     // Query database for passkey
  *     db.query("SELECT * FROM passkeys WHERE user_id = ? AND id = ?", userId, passkeyId)
  *   }
  *
  *   def list(userId: UserId): Future[List[Passkey]] = {
  *     // Query database for all user's passkeys
  *     db.query("SELECT * FROM passkeys WHERE user_id = ?", userId)
  *   }
  *
  *   def upsert(userId: UserId, passkey: Passkey): Future[Unit] = {
  *     // Insert or update passkey in database
  *     db.upsert("passkeys", passkey)
  *   }
  *
  *   def delete(userId: UserId, passkeyId: PasskeyId): Future[Unit] = {
  *     // Delete passkey from database
  *     db.delete("DELETE FROM passkeys WHERE user_id = ? AND id = ?", userId, passkeyId)
  *   }
  * }
  *   }}}
  */
trait PasskeyRepository {

  /** Get a single passkey by ID.
    *
    * This retrieves the complete passkey data including the credential record needed for authentication verification.
    *
    * @param userId
    *   ID of the user who owns the passkey
    * @param passkeyId
    *   WebAuthn credential ID of the passkey
    * @return
    *   Future containing the passkey, or a failed future if not found or access denied
    *
    * @example
    *   {{{
    * val passkey: Future[Passkey] = passkeyRepo.get(userId, passkeyId)
    * passkey.map { p =>
    *   println(s"Found passkey: ${p.name}")
    *   // Use p.credentialRecord for WebAuthn verification
    * }
    *   }}}
    */
  def get(userId: UserId, passkeyId: PasskeyId): Future[Passkey]

  /** List all passkeys for a user.
    *
    * Returns all passkeys owned by the specified user, including their metadata and credential records. This is useful
    * for displaying passkeys in account settings and for generating authentication options.
    *
    * @param userId
    *   ID of the user whose passkeys to list
    * @return
    *   Future containing a list of passkeys (may be empty)
    *
    * @example
    *   {{{
    * val passkeys: Future[List[Passkey]] = passkeyRepo.list(userId)
    * passkeys.map { list =>
    *   println(s"User has ${list.size} passkeys")
    *   list.foreach(p => println(s"  - ${p.name.value} (created ${p.createdAt})"))
    * }
    *   }}}
    */
  def list(userId: UserId): Future[List[Passkey]]

  /** Insert or update a passkey.
    *
    * This method handles both creating new passkeys (during registration) and updating existing ones (e.g., after
    * authentication to update the sign count and last used time).
    *
    * Implementations should use the passkey ID to determine whether to insert or update.
    *
    * @param userId
    *   ID of the user who owns the passkey
    * @param passkey
    *   The complete passkey data to upsert
    * @return
    *   Future that completes when the upsert is successful
    *
    * @example
    *   {{{
    * // Insert new passkey after registration
    * val newPasskey = Passkey.fromRegistration(passkeyId, name, credentialRecord)
    * passkeyRepo.upsert(userId, newPasskey)
    *
    * // Update existing passkey after authentication
    * for {
    *   passkey <- passkeyRepo.get(userId, passkeyId)
    *   updated = passkey.recordAuthentication(newSignCount)
    *   _ <- passkeyRepo.upsert(userId, updated)
    * } yield ()
    *   }}}
    */
  def upsert(userId: UserId, passkey: Passkey): Future[Unit]

  /** Delete a passkey.
    *
    * Removes the passkey from storage. Users should be able to delete passkeys they no longer use or that may have been
    * compromised.
    *
    * @param userId
    *   ID of the user who owns the passkey
    * @param passkeyId
    *   WebAuthn credential ID of the passkey to delete
    * @return
    *   Future that completes when the passkey is deleted, or fails if the passkey doesn't exist or doesn't belong to
    *   the user
    *
    * @example
    *   {{{
    * passkeyRepo.delete(userId, passkeyId).map { _ =>
    *   println("Passkey deleted successfully")
    * }.recover {
    *   case e: NoSuchElementException => println("Passkey not found")
    * }
    *   }}}
    */
  def delete(userId: UserId, passkeyId: PasskeyId): Future[Unit]
}
