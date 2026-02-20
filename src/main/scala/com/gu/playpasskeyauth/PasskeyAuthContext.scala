package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.models.WebAuthnConfig
import com.gu.playpasskeyauth.web.*
import play.api.mvc.ActionBuilder

/** A typeclass that encapsulates all the authentication context needed for passkey operations.
  *
  * This typeclass bundles together the action builder and extractors required for passkey authentication. By providing
  * a single `given` instance of this typeclass, you can simplify the dependency injection for PasskeyAuth.
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
  * @param webAuthnConfig
  *   Configuration for WebAuthn operations (algorithms, timeouts, authenticator selection, etc.). Defaults to
  *   [[com.gu.playpasskeyauth.models.WebAuthnConfig.default]] which is suitable for most applications.
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
  * // Bundle everything together
  * val ctx = PasskeyAuthContext(
  *   userAction = userAction,
  *   creationDataExtractor = summon,
  *   authenticationDataExtractor = summon,
  *   passkeyNameExtractor = summon
  * )
  *
  * // Pass ctx to PasskeyAuth
  * val passkeyAuth = new PasskeyAuth[MyUser, AnyContent](
  *   cc,
  *   HostApp("My App", new URI("https://myapp.example.com")),
  *   ctx,
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
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]],
    webAuthnConfig: WebAuthnConfig = WebAuthnConfig.default
)
