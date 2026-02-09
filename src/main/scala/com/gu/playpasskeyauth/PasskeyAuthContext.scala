package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.web.{
  AuthenticationDataExtractor,
  CreationDataExtractor,
  PasskeyNameExtractor,
  RequestWithUser
}
import play.api.mvc.ActionBuilder

/** A typeclass that encapsulates all the authentication context needed for passkey operations.
  *
  * This typeclass bundles together the action builder and extractors required for passkey authentication. By providing
  * a single `given` instance of this typeclass, you can simplify the dependency injection for PasskeyAuth.
  *
  * @tparam U
  *   The user type for which a [[com.gu.playpasskeyauth.models.User]] instance must be available
  *
  * @tparam B
  *   The body content type (typically `AnyContent`)
  *
  * @param userAction
  *   An action builder that extracts the authenticated user from requests
  *
  * @param creationDataExtractor
  *   Strategy for extracting passkey creation data from requests (data from `navigator.credentials.create()`)
  *
  * @param authenticationDataExtractor
  *   Strategy for extracting passkey authentication data from requests (data from `navigator.credentials.get()`)
  *
  * @param passkeyNameExtractor
  *   Strategy for extracting the user-provided passkey name from requests
  *
  * @example
  *   {{{
  * // Define your extractors as givens
  * given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  * given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  * given PasskeyNameExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
  *
  * // Create the user action
  * val userExtractor: UserExtractor[MyUser, AuthenticatedRequest] = _.user
  * val userAction = authAction.andThen(new UserAction(userExtractor))
  *
  * // Option 1: Explicitly bundle everything together
  * given PasskeyAuthContext[MyUser, AnyContent] = PasskeyAuthContext(
  *   userAction = userAction,
  *   creationDataExtractor = summon,
  *   authenticationDataExtractor = summon,
  *   passkeyNameExtractor = summon
  * )
  *
  * // Option 2: Use the convenience method to auto-summon extractors
  * given PasskeyAuthContext[MyUser, AnyContent] =
  *   PasskeyAuthContext.fromContext(userAction)
  *
  * // Now PasskeyAuth only needs ExecutionContext and PasskeyAuthContext
  * val passkeyAuth = new PasskeyAuth[MyUser, AnyContent](
  *   cc,
  *   HostApp("My App", new URI("https://myapp.example.com")),
  *   passkeyRepo,
  *   challengeRepo,
  *   routes.AccountController.settings()
  * )
  *   }}}
  */
case class PasskeyAuthContext[U, B](
    userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], B],
    creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
    authenticationDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]],
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]]
)

object PasskeyAuthContext {

  /** Creates a PasskeyAuthContext by summoning the extractors from the implicit scope.
    *
    * This is a convenience method that automatically pulls the extractors from context, so you don't need to explicitly
    * pass them if they're already available as givens.
    *
    * @example
    *   {{{
    * given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
    * given AuthenticationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
    * given PasskeyNameExtractor[[A] =>> RequestWithUser[MyUser, A]] = ...
    *
    * val userAction = authAction.andThen(new UserAction(myUserExtractor))
    *
    * // Automatically summons all the extractors from context
    * given PasskeyAuthContext[MyUser, AnyContent] =
    *   PasskeyAuthContext.fromContext(userAction)
    *   }}}
    */
  def fromContext[U, B](userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], B])(using
      creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
      authenticationDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]],
      passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]]
  ): PasskeyAuthContext[U, B] =
    PasskeyAuthContext(userAction, creationDataExtractor, authenticationDataExtractor, passkeyNameExtractor)
}
