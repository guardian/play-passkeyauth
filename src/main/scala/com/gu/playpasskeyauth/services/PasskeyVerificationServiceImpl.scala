package com.gu.playpasskeyauth.services

import com.gu.googleauth.UserIdentity
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
import play.api.libs.json.JsValue

import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration.{Duration, SECONDS}
import scala.jdk.CollectionConverters.*
import scala.util.Try

private[playpasskeyauth] class PasskeyVerificationServiceImpl(
    app: HostApp,
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

  private val authenticatorSelectionCriteria = {
    // Allow the widest possible range of authenticators
    val authenticatorAttachment: AuthenticatorAttachment = null
    new AuthenticatorSelectionCriteria(
      authenticatorAttachment,
      // Don't allow passkeys unknown to the server to be discovered at authentication time
      ResidentKeyRequirement.DISCOURAGED,
      UserVerificationRequirement.REQUIRED
    )
  }

  private val hints = Seq(CLIENT_DEVICE, SECURITY_KEY, HYBRID)

  private val attestation = AttestationConveyancePreference.DIRECT

  private val creationExtensions: AuthenticationExtensionsClientInputs[RegistrationExtensionClientInput] = null
  private val authExtensions: AuthenticationExtensionsClientInputs[AuthenticationExtensionClientInput] = null

  private val credType = PUBLIC_KEY

  // TODO why is this hardcoded?
  private val transports: Option[Set[AuthenticatorTransport]] = None

  def buildCreationOptions(user: UserIdentity): Future[PublicKeyCredentialCreationOptions] =
    for {
      passkeyIds <- passkeyRepo.loadPasskeyIds(user.username)
      challenge = generateChallenge()
      _ <- challengeRepo.insertRegistrationChallenge(user.username, challenge)
    } yield {
      val userInfo = new PublicKeyCredentialUserEntity(user.username.getBytes(UTF_8), user.username, user.username)
      val excludeCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialCreationOptions(
        relyingParty,
        userInfo,
        challenge,
        publicKeyCredentialParameters.asJava,
        timeout.toMillis,
        excludeCredentials.asJava,
        authenticatorSelectionCriteria,
        hints.asJava,
        attestation,
        creationExtensions
      )
    }

  def register(
      user: UserIdentity,
      passkeyName: String,
      creationResponse: JsValue
  ): Future[CredentialRecord] =
    for {
      // There's a potential race condition here if another request conflicts with it so would be better at DB level - but leaving it here for now
      _ <- passkeyRepo
        .loadPasskeyNames(user.username)
        .flatMap(names => {
          if (names.contains(passkeyName)) {
            Future.failed(new IllegalArgumentException(s"A passkey with the name '$passkeyName' already exists."))
          } else {
            Future.successful(())
          }
        })
      challenge <- challengeRepo.loadRegistrationChallenge(user.username)
      verified <- Future.fromTry(
        Try(
          webAuthnManager.verifyRegistrationResponseJSON(
            creationResponse.toString,
            new RegistrationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              publicKeyCredentialParameters.asJava,
              userVerificationRequired
            )
          )
        )
      )
      credentialRecord = new CredentialRecordImpl(
        verified.getAttestationObject,
        verified.getCollectedClientData,
        verified.getClientExtensions,
        verified.getTransports
      )
      _ <- passkeyRepo.insertPasskey(user.username, passkeyName, credentialRecord)
      _ <- challengeRepo.deleteRegistrationChallenge(user.username)
    } yield credentialRecord

  def buildAuthenticationOptions(user: UserIdentity): Future[PublicKeyCredentialRequestOptions] =
    for {
      passkeyIds <- passkeyRepo.loadPasskeyIds(user.username)
      challenge = generateChallenge()
      _ <- challengeRepo.insertAuthenticationChallenge(user.username, challenge)
    } yield {
      val rpId = app.host
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

  def verify(user: UserIdentity, authenticationResponse: JsValue): Future[AuthenticationData] =
    for {
      challenge <- challengeRepo.loadAuthenticationChallenge(user.username)
      authData <- Future.fromTry(Try(webAuthnManager.parseAuthenticationResponseJSON(authenticationResponse.toString)))
      credentialRecord <- passkeyRepo.loadPasskey(user.username, authData.getCredentialId)
      verifiedAuthData <- Future.fromTry(
        Try(
          webAuthnManager.verify(
            authData,
            new AuthenticationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              credentialRecord,
              List(authData.getCredentialId).asJava,
              userVerificationRequired
            )
          )
        )
      )
      _ <- challengeRepo.deleteAuthenticationChallenge(user.username)
      _ <- passkeyRepo.updateAuthenticationCount(
        user.username,
        verifiedAuthData.getCredentialId,
        verifiedAuthData.getAuthenticatorData.getSignCount
      )
      _ <- passkeyRepo.updateLastUsedTime(user.username, verifiedAuthData.getCredentialId, Instant.now())
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
