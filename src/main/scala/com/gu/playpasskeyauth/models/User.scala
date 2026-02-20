package com.gu.playpasskeyauth.models

/** Typeclass that provides passkey-relevant information about a user type.
  *
  * Implement this typeclass for your application's user type so that the passkey library can extract the information it
  * needs for WebAuthn operations.
  *
  * @tparam U
  *   The user type to provide passkey information for
  *
  * @example
  *   {{{
  * case class MyUser(email: String, name: String)
  *
  * given User[MyUser] with
  *   extension (u: MyUser)
  *     def id: UserId = UserId(u.email)
  *     def displayName: String = u.name
  *   }}}
  */
trait User[U] {
  extension (u: U) {

    /** The unique identifier for this user, used in all passkey storage and lookup operations. */
    def id: UserId

    /** The human-readable name displayed to the user in browser passkey dialogs during registration. */
    def displayName: String
  }
}
