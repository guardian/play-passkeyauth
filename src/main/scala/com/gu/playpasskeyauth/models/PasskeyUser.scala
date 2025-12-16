package com.gu.playpasskeyauth.models

/** Type class that defines how to extract an identifier from a user type.
  *
  * Client code should implement this for their user type to integrate with the passkey authentication system.
  *
  * Example:
  * {{{
  * case class MyUser(email: String, name: String)
  *
  * given PasskeyUser[MyUser] with
  *   extension (user: MyUser) def id: UserId = UserId(user.email)
  * }}}
  */
trait PasskeyUser[U] {
  extension (user: U) def id: UserId
}
