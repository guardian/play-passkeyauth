package com.gu.playpasskeyauth.models

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.attestation.authenticator.{AAGUID, AttestedCredentialData, COSEKey}
import com.webauthn4j.data.attestation.statement.{
  AttestationStatement,
  COSEAlgorithmIdentifier,
  COSEKeyOperation,
  COSEKeyType
}
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.data.extension.authenticator.{
  AuthenticationExtensionsAuthenticatorOutputs,
  RegistrationExtensionAuthenticatorOutput
}
import com.webauthn4j.data.extension.client.{AuthenticationExtensionsClientOutputs, RegistrationExtensionClientOutput}

import java.security.{PrivateKey, PublicKey}
import java.time.{Clock, Instant, ZoneOffset}
import java.util

/** Shared test fixtures for specs that work with [[Passkey]] and related types.
  *
  * Centralising these here avoids duplicating complex WebAuthn4J stub construction across test files and prevents
  * coupling between individual spec objects.
  */
object PasskeyTestFixtures {

  val fixedInstant: Instant = Instant.parse("2024-01-15T10:00:00Z")
  val fixedClock: Clock = Clock.fixed(fixedInstant, ZoneOffset.UTC)

  val sampleId: PasskeyId = PasskeyId(Array[Byte](1, 2, 3, 4, 5))
  val sampleName: PasskeyName = PasskeyName("Test Key")

  /** A minimal COSEKey implementation sufficient to satisfy AttestedCredentialData's non-null check. The key material
    * is irrelevant for model tests.
    */
  val stubCoseKey: COSEKey = new COSEKey {
    def getKeyType: COSEKeyType = null
    def getAlgorithm: COSEAlgorithmIdentifier = null
    def getKeyOperations: util.Set[COSEKeyOperation] = null
    def getKeyOps: util.List[COSEKeyOperation] = null
    def getKeyId: Array[Byte] = null
    def getBaseIV: Array[Byte] = null
    def validate(): Unit = ()
    def getPublicKey: PublicKey = null
    def getPrivateKey: PrivateKey = null
    def hasPublicKey: Boolean = false
    def hasPrivateKey: Boolean = false
  }

  val stubAttestedCredentialData: AttestedCredentialData =
    new AttestedCredentialData(AAGUID.ZERO, Array[Byte](1, 2, 3, 4, 5), stubCoseKey)

  val stubCredentialRecord: CredentialRecord = new CredentialRecord {
    def getAttestedCredentialData: AttestedCredentialData = stubAttestedCredentialData
    def getCounter: Long = 0L
    def setCounter(value: Long): Unit = ()
    def isUvInitialized: java.lang.Boolean = null
    def setUvInitialized(value: Boolean): Unit = ()
    def isBackupEligible: java.lang.Boolean = null
    def setBackupEligible(value: Boolean): Unit = ()
    def isBackedUp: java.lang.Boolean = null
    def setBackedUp(value: Boolean): Unit = ()
    def getClientData: CollectedClientData = null
    override def getAttestationStatement: AttestationStatement = null
    override def getAuthenticatorExtensions
        : AuthenticationExtensionsAuthenticatorOutputs[RegistrationExtensionAuthenticatorOutput] = null
    override def getClientExtensions: AuthenticationExtensionsClientOutputs[RegistrationExtensionClientOutput] = null
  }

  def samplePasskey(
      signCount: Long = 0L,
      lastUsedAt: Option[Instant] = None,
      createdAt: Instant = Instant.parse("2024-01-01T00:00:00Z")
  ): Passkey = Passkey(
    id = sampleId,
    name = sampleName,
    credentialRecord = stubCredentialRecord,
    createdAt = createdAt,
    lastUsedAt = lastUsedAt,
    signCount = signCount,
    aaguid = AAGUID.ZERO
  )
}
