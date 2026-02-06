package com.gu.playpasskeyauth.models

/** Type-safe wrapper for user identifiers.
  *
  * User IDs are strings that uniquely identify users in the passkey system.
  *
  * This type is obtained from a user via the [[UserIdExtractor]] function type.
  *
  * @param value
  *   The string identifier for the user (must not be empty or blank)
  * @throws IllegalArgumentException
  *   if value is null, empty, or contains only whitespace or leading or trailing whitespace.
  * @example
  *   {{{
  * // Given a UserIdExtractor for your user type:
  * given UserIdExtractor[MyUser] = user => UserId(user.email)
  *
  * // Use the ID in repository operations:
  * def loadPasskey(userId: UserId, passkeyId: PasskeyId): Future[CredentialRecord]
  *   }}}
  */
case class UserId(value: String) {
  require(value.trim.nonEmpty, "UserId must not be empty or blank")
  require(value.trim.length == value.length, "UserId must not have leading or trailing whitespace")

  /** Returns the underlying string value as bytes using UTF-8 encoding.
    *
    * Useful for WebAuthn operations that require byte arrays.
    */
  def bytes: Array[Byte] = value.getBytes(java.nio.charset.StandardCharsets.UTF_8)
}
