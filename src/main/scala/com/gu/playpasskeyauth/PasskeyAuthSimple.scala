package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.models.{Passkey, PasskeyAuthConfig, PasskeyId, PasskeyInfo, UserId}
import com.gu.playpasskeyauth.services.{
  PasskeyChallengeRepository,
  PasskeyRepository,
  PasskeyVerificationService,
  PasskeyVerificationServiceImpl
}
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.{AuthenticationData, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions}
import play.api.libs.json.JsValue

import scala.concurrent.{ExecutionContext, Future}

/** Simplified entry point for passkey authentication.
  *
  * This class provides direct access to passkey operations without complex action builders or type lambdas. Just create
  * an instance with your config and repositories, then call the methods directly.
  *
  * @param config
  *   Unified configuration for your application
  * @param passkeyRepo
  *   Repository for storing passkey credentials
  * @param challengeRepo
  *   Repository for storing temporary challenges
  * @param ec
  *   Execution context for async operations
  *
  * @example
  *   {{{
  * // Simple setup
  * val config = PasskeyAuthConfig.localhost("My App")
  * val passkeyAuth = new PasskeyAuthSimple(config, passkeyRepo, challengeRepo)
  *
  * // Create options for registration
  * val options = passkeyAuth.createOptions(userId, userName)
  *
  * // Register a new passkey
  * passkeyAuth.register(userId, "My YubiKey", credentialJson)
  *
  * // Verify authentication
  * val verified = passkeyAuth.verify(userId, assertionJson)
  *
  * // List passkeys
  * val passkeys = passkeyAuth.list(userId)
  *   }}}
  */
class PasskeyAuthSimple(
    val config: PasskeyAuthConfig,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository
)(using ec: ExecutionContext) {

  private val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(
      config.toHostApp,
      passkeyRepo,
      challengeRepo,
      config.toWebAuthnConfig
    )

  /** Create options for registering a new passkey.
    *
    * Call this endpoint when the user wants to register a new passkey. Pass the returned options to
    * `navigator.credentials.create()` in the browser.
    *
    * @param userId
    *   The user ID who is registering
    * @param userName
    *   Display name for the user (shown in WebAuthn prompts)
    * @return
    *   Options to pass to the browser's WebAuthn API
    *
    * @example
    *   {{{
    * // In your controller
    * def createOptions = Action.async { request =>
    *   val userId = extractUserId(request)
    *   val userName = extractUserName(request)
    *   passkeyAuth.createOptions(userId, userName).map { options =>
    *     Ok(Json.toJson(options))
    *   }
    * }
    *   }}}
    */
  def createOptions(userId: UserId, userName: String): Future[PublicKeyCredentialCreationOptions] = {
    verificationService.buildCreationOptions(userId, userName)
  }

  /** Register a new passkey for a user.
    *
    * Call this endpoint after the browser's `navigator.credentials.create()` succeeds. This verifies the credential and
    * stores it.
    *
    * @param userId
    *   The user ID who is registering
    * @param passkeyName
    *   A friendly name for this passkey (e.g., "My YubiKey", "iPhone")
    * @param credentialJson
    *   The JSON response from `navigator.credentials.create()`
    * @return
    *   The registered credential record
    *
    * @example
    *   {{{
    * // In your controller
    * def register = Action.async(parse.json) { request =>
    *   val userId = extractUserId(request)
    *   val name = (request.body \ "name").as[String]
    *   val credential = (request.body \ "credential").as[JsValue]
    *
    *   passkeyAuth.register(userId, name, credential).map { _ =>
    *     Ok("Registered")
    *   }
    * }
    *   }}}
    */
  def register(userId: UserId, passkeyName: String, credentialJson: JsValue): Future[CredentialRecord] = {
    verificationService.register(userId, passkeyName, credentialJson)
  }

  /** Create options for authenticating with a passkey.
    *
    * Call this endpoint when the user wants to authenticate. Pass the returned options to `navigator.credentials.get()`
    * in the browser.
    *
    * @param userId
    *   The user ID who is authenticating
    * @return
    *   Options to pass to the browser's WebAuthn API
    *
    * @example
    *   {{{
    * // In your controller
    * def authOptions = Action.async { request =>
    *   val userId = extractUserId(request)
    *   passkeyAuth.authOptions(userId).map { options =>
    *     Ok(Json.toJson(options))
    *   }
    * }
    *   }}}
    */
  def authOptions(userId: UserId): Future[PublicKeyCredentialRequestOptions] = {
    verificationService.buildAuthenticationOptions(userId)
  }

  /** Verify a passkey authentication attempt.
    *
    * Call this endpoint after the browser's `navigator.credentials.get()` succeeds. This verifies the signature and
    * updates the passkey metadata.
    *
    * @param userId
    *   The user ID who is authenticating
    * @param assertionJson
    *   The JSON response from `navigator.credentials.get()`
    * @return
    *   The verified authentication data
    *
    * @example
    *   {{{
    * // In your controller
    * def verify = Action.async(parse.json) { request =>
    *   val userId = extractUserId(request)
    *   val assertion = (request.body \ "assertion").as[JsValue]
    *
    *   passkeyAuth.verify(userId, assertion).map { authData =>
    *     Ok("Verified")
    *   }.recover {
    *     case e: PasskeyException => Unauthorized("Verification failed")
    *   }
    * }
    *   }}}
    */
  def verify(userId: UserId, assertionJson: JsValue): Future[AuthenticationData] = {
    verificationService.verify(userId, assertionJson)
  }

  /** List all passkeys registered for a user.
    *
    * Returns metadata about each passkey (ID, name, creation time, last used time) but not the credential itself.
    *
    * @param userId
    *   The user ID whose passkeys to list
    * @return
    *   List of passkey information
    *
    * @example
    *   {{{
    * // In your controller
    * def listPasskeys = Action.async { request =>
    *   val userId = extractUserId(request)
    *   passkeyAuth.list(userId).map { passkeys =>
    *     Ok(Json.toJson(passkeys))
    *   }
    * }
    *   }}}
    */
  def list(userId: UserId): Future[List[PasskeyInfo]] = {
    verificationService.listPasskeys(userId)
  }

  /** Delete a passkey.
    *
    * Removes the passkey from storage. Users should be able to delete passkeys they no longer use.
    *
    * @param userId
    *   The user ID who owns the passkey
    * @param passkeyId
    *   The ID of the passkey to delete
    * @return
    *   Future that completes when deleted
    *
    * @example
    *   {{{
    * // In your controller
    * def deletePasskey(passkeyIdBase64: String) = Action.async { request =>
    *   val userId = extractUserId(request)
    *   val passkeyId = PasskeyId.fromBase64Url(passkeyIdBase64)
    *
    *   passkeyAuth.delete(userId, passkeyId).map { _ =>
    *     NoContent
    *   }
    * }
    *   }}}
    */
  def delete(userId: UserId, passkeyId: PasskeyId): Future[Unit] = {
    verificationService.deletePasskey(userId, passkeyId)
  }

  /** Get full passkey data including credential.
    *
    * This is useful if you need direct access to the credential record.
    *
    * @param userId
    *   The user ID who owns the passkey
    * @param passkeyId
    *   The ID of the passkey
    * @return
    *   Complete passkey data
    */
  def get(userId: UserId, passkeyId: PasskeyId): Future[Passkey] = {
    passkeyRepo.get(userId, passkeyId)
  }

  /** List all complete passkey data including credentials.
    *
    * This returns full `Passkey` objects instead of just `PasskeyInfo` metadata.
    *
    * @param userId
    *   The user ID whose passkeys to list
    * @return
    *   List of complete passkey data
    */
  def listFull(userId: UserId): Future[List[Passkey]] = {
    passkeyRepo.list(userId)
  }
}

object PasskeyAuthSimple {

  /** Create a PasskeyAuthSimple with minimal configuration.
    *
    * @param appName
    *   Name of your application
    * @param appOrigin
    *   Origin URI of your application
    * @param passkeyRepo
    *   Repository for passkeys
    * @param challengeRepo
    *   Repository for challenges
    * @return
    *   Configured PasskeyAuthSimple instance
    */
  def apply(
      appName: String,
      appOrigin: java.net.URI,
      passkeyRepo: PasskeyRepository,
      challengeRepo: PasskeyChallengeRepository
  )(using ExecutionContext): PasskeyAuthSimple = {
    val config = PasskeyAuthConfig(appName, appOrigin)
    new PasskeyAuthSimple(config, passkeyRepo, challengeRepo)
  }
}
