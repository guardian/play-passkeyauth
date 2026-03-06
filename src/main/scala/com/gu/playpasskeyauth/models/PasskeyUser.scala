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
  * given PasskeyUser[MyUser] with
  *   extension (u: MyUser)
  *     def id: UserId = UserId(u.email)
  *     def displayName: String = u.name
  *   }}}
  */
trait PasskeyUser[U] {
  extension (u: U) {

    /** The unique identifier for this user, used in all passkey storage and lookup operations. */
    def id: UserId

    /** The human-readable name displayed to the user in browser passkey dialogs during registration. */
    def displayName: String
  }
}

object PasskeyUser {

  /** Summoner method — returns the [[PasskeyUser]] instance for `U` that is already in implicit scope.
    *
    * Useful for passing the instance explicitly where needed. For Guice `@Provides` methods, prefer importing the given
    * instances from your user type's companion:
    *
    * {{{
    * import models.User.given   // brings PasskeyUser[User] into scope
    * }}}
    */
  def apply[U](using instance: PasskeyUser[U]): PasskeyUser[U] = instance
}
