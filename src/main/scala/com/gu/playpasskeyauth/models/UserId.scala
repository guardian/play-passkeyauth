package com.gu.playpasskeyauth.models

/** Type-safe wrapper for user identifiers.
  *
  * User IDs are strings that uniquely identify users in the passkey system.
  *
  * This type is obtained from a user via the [[PasskeyUser]] type class.
  *
  * @example
  *   {{{
  * // Given a PasskeyUser instance for your user type:
  * given PasskeyUser[MyUser] with
  *   extension (user: MyUser) def id: UserId = UserId(user.email)
  *
  * // Use the ID in repository operations:
  * def loadPasskey(userId: UserId, passkeyId: PasskeyId): Future[CredentialRecord]
  *   }}}
  */
opaque type UserId = String

object UserId:

  /** Creates a UserId from a string value.
    *
    * @param value
    *   The string identifier for the user (must not be empty or blank)
    * @return
    *   A type-safe UserId
    * @throws IllegalArgumentException
    *   if value is null, empty, or contains only whitespace or leading or trailing whitespace.
    */
  def apply(value: String): UserId =
    require(value.trim.nonEmpty, "UserId must not be empty or blank")
    require(value.trim.length == value.length, "UserId must not have leading or trailing whitespace")
    value

  /** Extension methods for UserId */
  extension (userId: UserId)
    /** Returns the underlying string value.
      *
      * Use this when you need to pass the ID to external systems (e.g., database queries, JSON serialization).
      */
    def value: String = userId

    /** Returns the underlying string value as bytes using UTF-8 encoding.
      *
      * Useful for WebAuthn operations that require byte arrays.
      */
    def bytes: Array[Byte] = userId.getBytes(java.nio.charset.StandardCharsets.UTF_8)
