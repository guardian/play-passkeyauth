package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.HostApp
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.{CredentialRecord, CredentialRecordImpl}
import com.webauthn4j.data.*
import com.webauthn4j.data.PublicKeyCredentialHints.{CLIENT_DEVICE, HYBRID, SECURITY_KEY}
import com.webauthn4j.data.PublicKeyCredentialType.PUBLIC_KEY
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.challenge.{Challenge, DefaultChallenge}
import com.webauthn4j.data.extension.client.{
  AuthenticationExtensionClientInput,
  AuthenticationExtensionsClientInputs,
  RegistrationExtensionClientInput
}
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.util.Base64UrlUtil

import java.nio.charset.StandardCharsets.UTF_8
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration.{Duration, SECONDS}
import scala.jdk.CollectionConverters.*
import scala.util.Try

class PasskeyVerificationServiceImpl(
    app: com.gu.playpasskeyauth.models.HostApp,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    generateChallenge: () => Challenge = () => new DefaultChallenge()
) extends PasskeyVerificationService {

  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  private val userVerificationRequired = true
  private val userVerification = UserVerificationRequirement.REQUIRED

  private val relyingParty = new PublicKeyCredentialRpEntity(app.host, app.name)

  // In order of algorithms we prefer
  private val publicKeyCredentialParameters = List(
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

  private val timeout = Duration(60, SECONDS)

  private val authenticatorSelection = {
    // Allow the widest possible range of authenticators
    val authenticatorAttachment: AuthenticatorAttachment = null
    new AuthenticatorSelectionCriteria(
      authenticatorAttachment,
      ResidentKeyRequirement.DISCOURAGED, // Don't allow passkeys unknown to the server to be discovered at authentication time
      UserVerificationRequirement.REQUIRED
    )
  }

  private val hints = Seq(CLIENT_DEVICE, SECURITY_KEY, HYBRID)

  private val attestation = AttestationConveyancePreference.DIRECT

  private val creationExtensions: AuthenticationExtensionsClientInputs[RegistrationExtensionClientInput] = null
  private val authExtensions: AuthenticationExtensionsClientInputs[AuthenticationExtensionClientInput] = null

  private val credType = PUBLIC_KEY

  private val transports: Option[Set[AuthenticatorTransport]] = None

  // TODO: challenge in DB
  def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions] = {
    val userInfo = new PublicKeyCredentialUserEntity(userId.getBytes(UTF_8), userId, userId)
    val challenge = generateChallenge()
    passkeyRepo
      .loadPasskeyIds(userId)
      .map { passkeyIds =>
        val excludeCredentials = passkeyIds.map(toDescriptor)
        new PublicKeyCredentialCreationOptions(
          relyingParty,
          userInfo,
          challenge,
          publicKeyCredentialParameters.asJava,
          timeout.toMillis,
          excludeCredentials.asJava,
          authenticatorSelection,
          hints.asJava,
          attestation,
          creationExtensions
        )
      }
  }

  // TODO: challenge management and record in DB
  override def register(userId: String, jsonCreationResponse: String): Future[CredentialRecord] = {
    val regData = webAuthnManager.parseRegistrationResponseJSON(jsonCreationResponse)
    val challenge = generateChallenge()
    val regParams = new RegistrationParameters(
      new ServerProperty(
        app.origin,
        app.host,
        challenge
      ),
      publicKeyCredentialParameters.asJava,
      userVerificationRequired
    )
    val verified = webAuthnManager.verify(regData, regParams)
    Future.successful(
      new CredentialRecordImpl(
        verified.getAttestationObject,
        verified.getCollectedClientData,
        verified.getClientExtensions,
        verified.getTransports
      )
    )
  }

  // TODO: challenge in DB
  def authenticationOptions(userId: String): Future[PublicKeyCredentialRequestOptions] = {
    val challenge = generateChallenge()
    val rpId = app.host
    passkeyRepo.loadPasskeyIds(userId).map { passkeyIds =>
      val allowCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialRequestOptions(
        challenge,
        timeout.toMillis,
        rpId,
        allowCredentials.asJava,
        userVerification,
        hints.asJava,
        authExtensions
      )
    }
  }

  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData] =
    for {
      optChallenge <- challengeRepo.loadAuthenticationChallenge(userId)
      challenge <- optChallenge
        .map(c => Future.successful(c))
        .getOrElse(Future.failed(new RuntimeException("Challenge not found")))
      optPasskey <- passkeyRepo.loadCredentialRecord(userId, authData.getCredentialId)
      passkey <- optPasskey
        .map(p => Future.successful(p))
        .getOrElse(Future.failed(new RuntimeException("Passkey not found")))
      serverProps = new ServerProperty(app.origin, app.host, challenge)
      authParams = new AuthenticationParameters(
        serverProps,
        passkey,
        List(authData.getCredentialId).asJava,
        userVerificationRequired
      )
      verifiedAuthData <- Future.fromTry(Try(webAuthnManager.verify(authData, authParams)))
      _ <- challengeRepo.deleteAuthenticationChallenge(userId)
      _ <- passkeyRepo.updateAuthenticationCounter(userId, verifiedAuthData)
      _ <- passkeyRepo.updateLastUsedTime(userId, verifiedAuthData)
    } yield verifiedAuthData

  private def toDescriptor(passkeyId: String): PublicKeyCredentialDescriptor = {
    val id = Base64UrlUtil.decode(passkeyId)
    new PublicKeyCredentialDescriptor(
      credType,
      id,
      transports.map(_.asJava).orNull
    )
  }
}
