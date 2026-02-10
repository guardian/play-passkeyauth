package com.gu.playpasskeyauth.models

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data.*
import com.webauthn4j.data.PublicKeyCredentialHints.{CLIENT_DEVICE, HYBRID, SECURITY_KEY}
import com.webauthn4j.data.PublicKeyCredentialType.PUBLIC_KEY
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.client.{
  AuthenticationExtensionClientInput,
  AuthenticationExtensionsClientInputs,
  RegistrationExtensionClientInput
}

import scala.concurrent.duration.{Duration, SECONDS}

/** Pure configuration for WebAuthn passkey operations.
  *
  * This class captures all the static configuration needed for WebAuthn credential creation and authentication. All
  * values are immutable and pure, containing no side effects.
  *
  * @param publicKeyCredentialParameters
  *   List of acceptable public key algorithms in order of preference. Defaults to EdDSA, ES256, and RS256 for broad
  *   compatibility.
  *
  * @param timeout
  *   Maximum time allowed for credential operations in the browser. After this timeout, the browser will abort the
  *   operation.
  *
  * @param authenticatorSelectionCriteria
  *   Criteria for selecting authenticators during credential creation. Controls whether platform authenticators (like
  *   FaceID) or roaming authenticators (like YubiKey) are preferred.
  *
  * @param hints
  *   Hints to help the browser/OS select the appropriate authenticator UI. Examples: CLIENT_DEVICE for platform
  *   authenticators, SECURITY_KEY for USB keys, HYBRID for cross-device authentication.
  *
  * @param attestation
  *   Attestation conveyance preference. DIRECT requests attestation from the authenticator, NONE skips it. Attestation
  *   provides cryptographic proof of the authenticator's make and model.
  *
  * @param creationExtensions
  *   Optional WebAuthn extensions for credential creation. None means no extensions.
  *
  * @param authExtensions
  *   Optional WebAuthn extensions for authentication. None means no extensions.
  *
  * @param userVerificationRequired
  *   Whether user verification (PIN, biometric, etc.) is required by the relying party. This is enforced on the server
  *   side during verification.
  *
  * @param userVerification
  *   User verification requirement sent to the browser. Should match userVerificationRequired.
  *
  * @param credentialType
  *   The type of credential. Always PUBLIC_KEY for passkeys.
  *
  * @param transports
  *   Optional set of allowed authenticator transports. None means all transports are allowed.
  */
case class WebAuthnConfig(
    manager: WebAuthnManager,
    publicKeyCredentialParameters: List[PublicKeyCredentialParameters],
    timeout: Duration,
    authenticatorSelectionCriteria: AuthenticatorSelectionCriteria,
    hints: Seq[PublicKeyCredentialHints],
    attestation: AttestationConveyancePreference,
    creationExtensions: Option[AuthenticationExtensionsClientInputs[RegistrationExtensionClientInput]],
    authExtensions: Option[AuthenticationExtensionsClientInputs[AuthenticationExtensionClientInput]],
    userVerificationRequired: Boolean,
    userVerification: UserVerificationRequirement,
    credentialType: PublicKeyCredentialType,
    transports: Option[Set[AuthenticatorTransport]]
)

object WebAuthnConfig {

  /** Default WebAuthn configuration suitable for most applications.
    *
    * This configuration:
    *   - Accepts EdDSA, ES256, and RS256 algorithms (in order of preference)
    *   - Requires user verification (PIN/biometric)
    *   - Allows 60 seconds for credential operations
    *   - Supports all authenticator types (platform and roaming)
    *   - Discourages resident keys to prevent credential discovery
    */
  val default: WebAuthnConfig = {
    // In order of algorithms we prefer
    val publicKeyCredentialParameters = List(
      // EdDSA for better security/performance in newer authenticators
      new PublicKeyCredentialParameters(
        PUBLIC_KEY,
        COSEAlgorithmIdentifier.EdDSA
      ),
      // ES256 is widely supported and efficient
      new PublicKeyCredentialParameters(
        PUBLIC_KEY,
        COSEAlgorithmIdentifier.ES256
      ),
      // RS256 for broader compatibility
      new PublicKeyCredentialParameters(
        PUBLIC_KEY,
        COSEAlgorithmIdentifier.RS256
      )
    )

    val authenticatorSelectionCriteria = {
      // null means "no preference" in the WebAuthn Java API - allows both platform and roaming authenticators
      val authenticatorAttachment: AuthenticatorAttachment = null
      new AuthenticatorSelectionCriteria(
        authenticatorAttachment,
        // Don't allow passkeys unknown to the server to be discovered at authentication time
        ResidentKeyRequirement.DISCOURAGED,
        UserVerificationRequirement.REQUIRED
      )
    }

    WebAuthnConfig(
      manager = WebAuthnManager.createNonStrictWebAuthnManager(),
      publicKeyCredentialParameters = publicKeyCredentialParameters,
      timeout = Duration(60, SECONDS),
      authenticatorSelectionCriteria = authenticatorSelectionCriteria,
      hints = Seq(CLIENT_DEVICE, SECURITY_KEY, HYBRID),
      attestation = AttestationConveyancePreference.DIRECT,
      creationExtensions = None,
      authExtensions = None,
      userVerificationRequired = true,
      userVerification = UserVerificationRequirement.REQUIRED,
      credentialType = PUBLIC_KEY,
      transports = None
    )
  }
}
