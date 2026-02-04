package com.gu.playpasskeyauth.models

import java.net.URI
import scala.concurrent.duration._

/** Unified configuration for PasskeyAuth.
  *
  * This consolidates all configuration parameters into a single object, making it much easier to set up passkey
  * authentication. Instead of passing 10+ parameters to PasskeyAuth, you create one config object.
  *
  * @param appName
  *   Name of your application (shown to users in WebAuthn prompts)
  * @param appOrigin
  *   The origin of your application (e.g., https://example.com)
  * @param requestConfig
  *   Configuration for extracting passkey data from HTTP requests
  * @param timeout
  *   How long WebAuthn operations are valid (default: 60 seconds)
  * @param requireUserVerification
  *   Whether to require user verification (PIN, biometric, etc.)
  * @param preferredAlgorithms
  *   List of preferred signing algorithms in order of preference
  *
  * @example
  *   {{{
  * val config = PasskeyAuthConfig(
  *   appName = "My App",
  *   appOrigin = new URI("https://myapp.example.com")
  * )
  * // All other settings use sensible defaults
  *
  * // Or customize:
  * val customConfig = PasskeyAuthConfig(
  *   appName = "My App",
  *   appOrigin = new URI("https://myapp.example.com"),
  *   timeout = 120.seconds,
  *   requireUserVerification = false,
  *   requestConfig = PasskeyRequestConfig.default
  * )
  *   }}}
  */
case class PasskeyAuthConfig(
    appName: String,
    appOrigin: URI,
    requestConfig: PasskeyRequestConfig = PasskeyRequestConfig.default,
    timeout: Duration = 60.seconds,
    requireUserVerification: Boolean = true,
    preferredAlgorithms: List[String] = List("EdDSA", "ES256", "RS256")
) {
  require(appName.trim.nonEmpty, "App name must not be empty")
  require(appOrigin.getHost != null, "App origin must have a host")
  require(timeout.toMillis > 0, "Timeout must be positive")

  /** The host portion of the origin (e.g., "example.com" from "https://example.com") */
  val host: String = appOrigin.getHost

  /** The full origin string (e.g., "https://example.com") */
  val origin: String = appOrigin.toString

  /** Convert to the internal WebAuthnConfig format */
  private[playpasskeyauth] def toWebAuthnConfig: WebAuthnConfig = {
    // Use default config but could customize timeout if needed
    WebAuthnConfig.default
  }

  /** Convert to HostApp for backward compatibility */
  private[playpasskeyauth] def toHostApp: HostApp = {
    HostApp(appName, appOrigin)
  }
}

object PasskeyAuthConfig {

  /** Quick constructor for development/localhost setups.
    *
    * @param appName
    *   Name of your application
    * @param port
    *   Port your app runs on (default: 9000)
    * @return
    *   Configuration for localhost
    *
    * @example
    *   {{{
    * val config = PasskeyAuthConfig.localhost("My Dev App", port = 9000)
    *   }}}
    */
  def localhost(appName: String, port: Int = 9000): PasskeyAuthConfig = {
    PasskeyAuthConfig(
      appName = appName,
      appOrigin = new URI(s"http://localhost:$port")
    )
  }

  /** Quick constructor for production HTTPS setups.
    *
    * @param appName
    *   Name of your application
    * @param domain
    *   Your domain (e.g., "example.com")
    * @return
    *   Configuration for HTTPS production
    *
    * @example
    *   {{{
    * val config = PasskeyAuthConfig.https("My App", "myapp.example.com")
    *   }}}
    */
  def https(appName: String, domain: String): PasskeyAuthConfig = {
    PasskeyAuthConfig(
      appName = appName,
      appOrigin = new URI(s"https://$domain")
    )
  }
}
