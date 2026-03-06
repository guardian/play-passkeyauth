package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.models.WebAuthnConfig
import com.gu.playpasskeyauth.web.*
import play.api.libs.json.JsValue
import play.api.mvc.{ActionBuilder, Request}

/** A context object that bundles all the configuration needed for passkey operations.
  *
  * Provide an instance of this to [[PasskeyAuth]] to wire together your application's authentication with the passkey
  * library.
  *
  * @tparam U
  *   The user type representing the authenticated user
  *
  * @tparam B
  *   The body content type (typically `AnyContent`)
  *
  * @param actionBuilder
  *   The base action builder used to build passkey actions (e.g., your existing authenticated action, or
  *   `DefaultActionBuilder`). The library will compose user extraction on top of this.
  *
  * @param userExtractor
  *   A function that extracts the authenticated user from any incoming request. For example, if your requests carry a
  *   user in a session or a prior action result: `request => request.attrs(UserKey)`
  *
  * @param creationDataExtractor
  *   Extracts the WebAuthn creation response JSON (from `navigator.credentials.create()`) from a [[RequestWithUser]].
  *   Typically reads a field from the JSON request body.
  *
  * @param authenticationDataExtractor
  *   Extracts the WebAuthn assertion JSON (from `navigator.credentials.get()`) from a [[RequestWithUser]]. Typically
  *   reads a field from the JSON request body.
  *
  * @param passkeyNameExtractor
  *   Extracts the user-provided passkey name from a [[RequestWithUser]]. Typically reads a field from the JSON request
  *   body.
  *
  * @param webAuthnConfig
  *   Configuration for WebAuthn operations (algorithms, timeouts, authenticator selection, etc.). Defaults to
  *   [[com.gu.playpasskeyauth.models.WebAuthnConfig.default]] which is suitable for most applications.
  *
  * @example
  *   {{{
  * val ctx = PasskeyAuthContext(
  *   actionBuilder               = defaultActionBuilder,
  *   userExtractor               = _ => User.demo,               // or: req => req.attrs(UserKey)
  *   creationDataExtractor       = req => req.body.asJson.flatMap(j => (j \ "credential").asOpt[JsValue]),
  *   authenticationDataExtractor = req => req.body.asJson.flatMap(j => (j \ "assertion").asOpt[JsValue]),
  *   passkeyNameExtractor        = req => req.body.asJson.flatMap(j => (j \ "name").asOpt[String])
  * )
  *   }}}
  */
case class PasskeyAuthContext[U, B](
    actionBuilder: ActionBuilder[Request, B],
    userExtractor: Request[?] => U,
    creationDataExtractor: RequestWithUser[U, ?] => Option[JsValue],
    authenticationDataExtractor: RequestWithUser[U, ?] => Option[JsValue],
    passkeyNameExtractor: RequestWithUser[U, ?] => Option[String],
    webAuthnConfig: WebAuthnConfig = WebAuthnConfig.default
)
