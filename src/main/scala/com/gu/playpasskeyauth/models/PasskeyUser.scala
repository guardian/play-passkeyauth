package com.gu.playpasskeyauth.models

/** Function type for extracting a UserId from a user object.
  *
  * This replaces the more complex type class approach with a simple function type. Client code provides a function that
  * extracts the user ID from their user type.
  *
  * Example:
  * {{{
  * case class MyUser(email: String, name: String)
  *
  * // Define how to extract UserId from MyUser
  * given UserIdExtractor[MyUser] = user => UserId(user.email)
  *
  * // Or as an explicit function
  * val extractUserId: UserIdExtractor[MyUser] = user => UserId(user.email)
  * }}}
  */
type UserIdExtractor[U] = U => UserId

object UserIdExtractor {

  /** Helper to extract a UserId from a user using an implicit extractor.
    *
    * @param user
    *   The user instance from which to extract the identifier
    * @param extractor
    *   The extractor function (resolved implicitly)
    * @return
    *   The extracted UserId
    * @example
    *   {{{
    * case class MyUser(email: String, name: String)
    * given UserIdExtractor[MyUser] = user => UserId(user.email)
    *
    * val user = MyUser("alice@example.com", "Alice")
    * val userId = UserIdExtractor.extractFrom(user)
    *   }}}
    */
  def extractFrom[U](user: U)(using extractor: UserIdExtractor[U]): UserId =
    extractor(user)
}
