package com.gu.playpasskeyauth.web

import com.gu.playpasskeyauth.models.PasskeyRequestConfig
import play.api.libs.json.JsValue
import play.api.mvc.Request

/** Simple implementation of CreationDataExtractor that uses PasskeyRequestConfig.
  *
  * This eliminates the need for users to implement the trait manually for standard JSON requests.
  *
  * @param config
  *   The configuration defining how to extract data from requests
  *
  * @example
  *   {{{
  * // Instead of implementing the trait:
  * given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] with {
  *   def findCreationData[A](request: RequestWithUser[MyUser, A]): Option[JsValue] =
  *     request.body.asJson.flatMap(js => (js \ "credential").asOpt[JsValue])
  * }
  *
  * // Just use the config-based implementation:
  * given CreationDataExtractor[[A] =>> RequestWithUser[MyUser, A]] =
  *   ConfigBasedCreationDataExtractor(PasskeyRequestConfig.default)
  *   }}}
  */
class ConfigBasedCreationDataExtractor[R[_] <: Request[_]](config: PasskeyRequestConfig)
    extends CreationDataExtractor[R] {
  def findCreationData[A](request: R[A]): Option[JsValue] =
    config.extractCredential(request)
}

object ConfigBasedCreationDataExtractor {
  def apply[R[_] <: Request[_]](config: PasskeyRequestConfig): ConfigBasedCreationDataExtractor[R] =
    new ConfigBasedCreationDataExtractor[R](config)

  /** Create with default configuration */
  def default[R[_] <: Request[_]]: ConfigBasedCreationDataExtractor[R] =
    new ConfigBasedCreationDataExtractor[R](PasskeyRequestConfig.default)
}

/** Simple implementation of PasskeyNameExtractor that uses PasskeyRequestConfig.
  *
  * @param config
  *   The configuration defining how to extract data from requests
  */
class ConfigBasedPasskeyNameExtractor[R[_] <: Request[_]](config: PasskeyRequestConfig)
    extends PasskeyNameExtractor[R] {
  def findPasskeyName[A](request: R[A]): Option[String] =
    config.extractPasskeyName(request)
}

object ConfigBasedPasskeyNameExtractor {
  def apply[R[_] <: Request[_]](config: PasskeyRequestConfig): ConfigBasedPasskeyNameExtractor[R] =
    new ConfigBasedPasskeyNameExtractor[R](config)

  /** Create with default configuration */
  def default[R[_] <: Request[_]]: ConfigBasedPasskeyNameExtractor[R] =
    new ConfigBasedPasskeyNameExtractor[R](PasskeyRequestConfig.default)
}

/** Simple implementation of AuthenticationDataExtractor that uses PasskeyRequestConfig.
  *
  * @param config
  *   The configuration defining how to extract data from requests
  */
class ConfigBasedAuthenticationDataExtractor[R[_] <: Request[_]](config: PasskeyRequestConfig)
    extends AuthenticationDataExtractor[R] {
  def findAuthenticationData[A](request: R[A]): Option[JsValue] =
    config.extractAssertion(request)
}

object ConfigBasedAuthenticationDataExtractor {
  def apply[R[_] <: Request[_]](config: PasskeyRequestConfig): ConfigBasedAuthenticationDataExtractor[R] =
    new ConfigBasedAuthenticationDataExtractor[R](config)

  /** Create with default configuration */
  def default[R[_] <: Request[_]]: ConfigBasedAuthenticationDataExtractor[R] =
    new ConfigBasedAuthenticationDataExtractor[R](PasskeyRequestConfig.default)
}
