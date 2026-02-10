package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.*
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
    webAuthn: WebAuthnConfig = WebAuthnConfig.default,
    generateChallenge: () => Challenge = () => new DefaultChallenge(),
    clock: Clock = Clock.systemUTC()
)(using ExecutionContext)
    extends PasskeyVerificationService {

  override def buildCreationOptions(userId: UserId, userName: String): Future[PublicKeyCredentialCreationOptions] =
    for {
      passkeys <- passkeyRepo.list(userId)
      passkeyIds = passkeys.map(_.id)
      challenge = generateChallenge()
      expiresAt = clock.instant().plusMillis(webAuthn.timeout.toMillis)
      _ <- challengeRepo.insertRegistrationChallenge(userId, challenge, expiresAt)
    } yield {
      val userInfo = new PublicKeyCredentialUserEntity(userId.bytes, userId.value, userName)
      val excludeCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialCreationOptions(
        relyingParty,
        userInfo,
        challenge,
        webAuthn.publicKeyCredentialParameters.asJava,
        webAuthn.timeout.toMillis,
        excludeCredentials.asJava,
        webAuthn.authenticatorSelectionCriteria,
        webAuthn.hints.asJava,
        webAuthn.attestation,
        webAuthn.creationExtensions.orNull
      )
    }

  override def registerPasskey(
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
          webAuthn.manager.verifyRegistrationResponseJSON(
            creationResponse.toString,
            new RegistrationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              webAuthn.publicKeyCredentialParameters.asJava,
              webAuthn.userVerificationRequired
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

  override def buildAuthenticationOptions(userId: UserId): Future[PublicKeyCredentialRequestOptions] =
    for {
      passkeys <- passkeyRepo.list(userId)
      passkeyIds = passkeys.map(_.id)
      challenge = generateChallenge()
      expiresAt = clock.instant().plusMillis(webAuthn.timeout.toMillis)
      _ <- challengeRepo.insertAuthenticationChallenge(userId, challenge, expiresAt)
    } yield {
      val rpId = app.host
      val allowCredentials = passkeyIds.map(toDescriptor)
      new PublicKeyCredentialRequestOptions(
        challenge,
        webAuthn.timeout.toMillis,
        rpId,
        allowCredentials.asJava,
        webAuthn.userVerification,
        webAuthn.hints.asJava,
        webAuthn.authExtensions.orNull
      )
    }

  override def verifyPasskey(userId: UserId, authenticationResponse: JsValue): Future[AuthenticationData] =
    for {
      challenge <- challengeRepo.loadAuthenticationChallenge(userId)
      authData <- Future.fromTry(Try(webAuthn.manager.parseAuthenticationResponseJSON(authenticationResponse.toString)))
      credentialId = PasskeyId(authData.getCredentialId)
      passkey <- passkeyRepo.get(userId, credentialId)
      verifiedAuthData <- Future.fromTry(
        Try(
          webAuthn.manager.verify(
            authData,
            new AuthenticationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              passkey.credentialRecord,
              List(authData.getCredentialId).asJava,
              webAuthn.userVerificationRequired
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

  override def listPasskeys(userId: UserId): Future[List[Passkey]] =
    passkeyRepo.list(userId)

  override def deletePasskey(userId: UserId, passkeyId: PasskeyId): Future[Unit] =
    passkeyRepo.delete(userId, passkeyId)

  private val relyingParty = new PublicKeyCredentialRpEntity(app.host, app.name)

  private def toDescriptor(passkeyId: PasskeyId): PublicKeyCredentialDescriptor =
    new PublicKeyCredentialDescriptor(
      webAuthn.credentialType,
      passkeyId.bytes,
      webAuthn.transports.map(_.asJava).orNull
    )
}
