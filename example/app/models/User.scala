package models

import com.gu.playpasskeyauth.models.{User as PasskeyUser, UserId}

/** Simple user model for the example application.
  *
  * In a real application, this would be your existing user model with more fields like name, email, profile data, etc.
  *
  * @param id
  *   Unique identifier for the user (used as the WebAuthn user ID)
  * @param username
  *   Display name for the user (shown in WebAuthn prompts)
  */
case class User(id: String, username: String)

object User {

  /** Defines how to extract passkey user information from a User for passkey operations. */
  given PasskeyUser[User] with {
    extension (u: User) {
      def id: UserId = UserId(u.id)
      def displayName: String = u.username
    }
  }

  /** Demo user for the example application.
    *
    * In a real application, users would be stored in a database and retrieved via authentication.
    */
  val demo: User = User(id = "demo-user-123", username = "Demo User")
}
