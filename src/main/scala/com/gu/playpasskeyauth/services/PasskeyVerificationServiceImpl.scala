package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{HostApp, Passkey, PasskeyId, PasskeyInfo, PasskeyName, UserId, WebAuthnConfig}
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.{CredentialRecord, CredentialRecordImpl}
import com.webauthn4j.data.*
import com.webauthn4j.data.client.challenge.{Challenge, DefaultChallenge}
import com.webauthn4j.server.ServerProperty
import play.api.libs.json.JsValue

import java.time.Clock
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters.*
import scala.util.Try

private[playpasskeyauth] class PasskeyVerificationServiceImpl(
    app: HostApp,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    config: WebAuthnConfig = WebAuthnConfig.default,
    generateChallenge: () => Challenge = () => new DefaultChallenge(),
    clock: Clock = Clock.systemUTC()
)(using ExecutionContext)
    extends PasskeyVerificationService {

  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  private val relyingParty = new PublicKeyCredentialRpEntity(app.host, app.name)

  def buildCreationOptions(userId: UserId, userName: String): Future[PublicKeyCredentialCreationOptions] =
    for {
      passkeys <- passkeyRepo.list(userId)
      passkeyIds = passkeys.map(_.id)
      challenge = generateChallenge()
      expiresAt = clock.instant().plusMillis(config.timeout.toMillis)
      _ <- challengeRepo.insertRegistrationChallenge(userId, challenge, expiresAt)
    } yield {
      val userInfo = new PublicKeyCredentialUserEntity(userId.bytes, userId.value, userName)
      val excludeCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialCreationOptions(
        relyingParty,
        userInfo,
        challenge,
        config.publicKeyCredentialParameters.asJava,
        config.timeout.toMillis,
        excludeCredentials.asJava,
        config.authenticatorSelectionCriteria,
        config.hints.asJava,
        config.attestation,
        config.creationExtensions.orNull
      )
    }

  def register(
      userId: UserId,
      passkeyName: String,
      creationResponse: JsValue
  ): Future[CredentialRecord] =
    for {
      // Validate and sanitise the passkey name
      validatedName <- PasskeyName.validate(passkeyName) match {
        case Right(name) => Future.successful(name)
        case Left(error) => Future.failed(PasskeyException(PasskeyError.InvalidName(error)))
      }
      // Check for duplicate name (potential race condition here to sort out)
      existingPasskeys <- passkeyRepo.list(userId)
      _ <-
        if existingPasskeys.exists(_.name.value == validatedName.value) then
          Future.failed(PasskeyException(PasskeyError.DuplicateName(validatedName.value)))
        else Future.successful(())

      challenge <- challengeRepo.loadRegistrationChallenge(userId)
      verified <- Future.fromTry(
        Try(
          webAuthnManager.verifyRegistrationResponseJSON(
            creationResponse.toString,
            new RegistrationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              config.publicKeyCredentialParameters.asJava,
              config.userVerificationRequired
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
      passkeyId = PasskeyId(
        verified.getAttestationObject.getAuthenticatorData.getAttestedCredentialData.getCredentialId
      )
      newPasskey = Passkey.fromRegistration(passkeyId, validatedName, credentialRecord, clock)
      _ <- passkeyRepo.upsert(userId, newPasskey)
      _ <- challengeRepo.deleteRegistrationChallenge(userId)
    } yield credentialRecord

  def buildAuthenticationOptions(userId: UserId): Future[PublicKeyCredentialRequestOptions] =
    for {
      passkeys <- passkeyRepo.list(userId)
      passkeyIds = passkeys.map(_.id)
      challenge = generateChallenge()
      expiresAt = clock.instant().plusMillis(config.timeout.toMillis)
      _ <- challengeRepo.insertAuthenticationChallenge(userId, challenge, expiresAt)
    } yield {
      val rpId = app.host
      val allowCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialRequestOptions(
        challenge,
        config.timeout.toMillis,
        rpId,
        allowCredentials.asJava,
        config.userVerification,
        config.hints.asJava,
        config.authExtensions.orNull
      )
    }

  def verify(userId: UserId, authenticationResponse: JsValue): Future[AuthenticationData] =
    for {
      challenge <- challengeRepo.loadAuthenticationChallenge(userId)
      authData <- Future.fromTry(Try(webAuthnManager.parseAuthenticationResponseJSON(authenticationResponse.toString)))
      credentialId = PasskeyId(authData.getCredentialId)
      passkey <- passkeyRepo.get(userId, credentialId)
      verifiedAuthData <- Future.fromTry(
        Try(
          webAuthnManager.verify(
            authData,
            new AuthenticationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              passkey.credentialRecord,
              List(authData.getCredentialId).asJava,
              config.userVerificationRequired
            )
          )
        )
      )
      verifiedCredentialId = PasskeyId(verifiedAuthData.getCredentialId)
      newSignCount = verifiedAuthData.getAuthenticatorData.getSignCount
      updatedPasskey = passkey.recordAuthentication(newSignCount, clock)
      _ <- challengeRepo.deleteAuthenticationChallenge(userId)
      _ <- passkeyRepo.upsert(userId, updatedPasskey)
    } yield verifiedAuthData

  def listPasskeys(userId: UserId): Future[List[PasskeyInfo]] =
    passkeyRepo.list(userId).map(_.map(_.toInfo))

  def deletePasskey(userId: UserId, passkeyId: PasskeyId): Future[Unit] =
    passkeyRepo.delete(userId, passkeyId)

  private def toDescriptor(passkeyId: PasskeyId): PublicKeyCredentialDescriptor =
    new PublicKeyCredentialDescriptor(
      config.credentialType,
      passkeyId.bytes,
      config.transports.map(_.asJava).orNull
    )
}
