package com.gu.playpasskeyauth.models

import com.webauthn4j.data.client.Origin

import java.net.URI

/** Represents the host application (relying party) for WebAuthn operations.
  *
  * In WebAuthn terminology, the "relying party" is the website or application that wants to authenticate users via
  * passkeys. This class captures the essential identity information needed for passkey registration and authentication.
  *
  * @param name
  *   The human-readable name of the application. This is displayed to users during passkey registration in browser
  *   dialogs. Examples: "My App", "Example Corp Portal", "Development Environment"
  *
  * @param uri
  *   The base URI of the application. The host from this URI is used as the relying party ID, and the origin is used
  *   for verifying WebAuthn responses. Examples:
  *   - Production: `new URI("https://myapp.example.com")`
  *   - Development: `new URI("https://localhost:9000")`
  *   - With port: `new URI("https://dev.example.com:8443")`
  *
  * @example
  *   {{{
  * // Production configuration
  * val productionApp = HostApp(
  *   name = "My Production App",
  *   uri = new URI("https://myapp.example.com")
  * )
  *
  * // Local development
  * val devApp = HostApp(
  *   name = "My App (Dev)",
  *   uri = new URI("https://localhost:9000")
  * )
  *   }}}
  */
case class HostApp(name: String, uri: URI) {

  /** The host portion of the URI, used as the relying party ID. For example: "myapp.example.com" or "localhost"
    */
  val host: String = uri.getHost

  /** The origin for WebAuthn verification, derived from the URI. This is used to verify that authentication responses
    * come from the expected origin.
    */
  val origin: Origin = Origin.create(uri.toString)
}
