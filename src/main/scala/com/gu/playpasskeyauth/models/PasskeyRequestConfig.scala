package com.gu.playpasskeyauth.models

import play.api.libs.json.{JsValue, Json}
import play.api.mvc.{AnyContent, Request}

/** Simple configuration for extracting passkey data from HTTP requests.
  *
  * This provides default extractors that work with standard JSON request bodies, reducing the boilerplate needed for
  * basic setups. Advanced users can still implement the extractor traits for custom behavior.
  *
  * @param extractCredential
  *   Function to extract WebAuthn credential data from a request. Default looks for `credential` field in JSON body.
  *
  * @param extractPasskeyName
  *   Function to extract the passkey name from a request. Default looks for `name` field in JSON body.
  *
  * @param extractAssertion
  *   Function to extract WebAuthn assertion data from a request. Default looks for `assertion` field in JSON body.
  *
  * @example
  *   Standard JSON format:
  *   {{{
  * // Registration request:
  * {
  *   "name": "My YubiKey",
  *   "credential": { ... WebAuthn credential data ... }
  * }
  *
  * // Authentication request:
  * {
  *   "assertion": { ... WebAuthn assertion data ... }
  * }
  *   }}}
  *
  * @example
  *   Custom extraction:
  *   {{{
  * val customConfig = PasskeyRequestConfig(
  *   extractCredential = req => extractJson(req).flatMap(js => (js \ "webauthn" \ "cred").asOpt[JsValue]),
  *   extractPasskeyName = req => extractJson(req).flatMap(js => (js \ "deviceName").asOpt[String]),
  *   extractAssertion = req => extractJson(req).flatMap(js => (js \ "webauthn" \ "auth").asOpt[JsValue])
  * )
  *   }}}
  */
case class PasskeyRequestConfig(
    extractCredential: Request[_] => Option[JsValue] = PasskeyRequestConfig.defaultExtractCredential,
    extractPasskeyName: Request[_] => Option[String] = PasskeyRequestConfig.defaultExtractPasskeyName,
    extractAssertion: Request[_] => Option[JsValue] = PasskeyRequestConfig.defaultExtractAssertion
)

object PasskeyRequestConfig {

  /** Helper to extract JSON from various request body types */
  private def extractJson(req: Request[_]): Option[JsValue] = {
    req.body match {
      case body: AnyContent => body.asJson
      case body: JsValue    => Some(body)
      case body: String     =>
        try Some(Json.parse(body))
        catch case _: Exception => None
      case _ => None
    }
  }

  private def defaultExtractCredential(req: Request[_]): Option[JsValue] =
    extractJson(req).flatMap(js => (js \ "credential").asOpt[JsValue])

  private def defaultExtractPasskeyName(req: Request[_]): Option[String] =
    extractJson(req).flatMap(js => (js \ "name").asOpt[String])

  private def defaultExtractAssertion(req: Request[_]): Option[JsValue] =
    extractJson(req).flatMap(js => (js \ "assertion").asOpt[JsValue])

  /** Default configuration for standard JSON requests.
    *
    * Expects:
    *   - Registration: `{ "name": "...", "credential": {...} }`
    *   - Authentication: `{ "assertion": {...} }`
    */
  val default: PasskeyRequestConfig = PasskeyRequestConfig()
}
