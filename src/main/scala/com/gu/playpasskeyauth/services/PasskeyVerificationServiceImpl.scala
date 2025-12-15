package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{HostApp, PasskeyId, PasskeyInfo, PasskeyName, PasskeyUser, UserId, WebAuthnConfig}
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

private[playpasskeyauth] class PasskeyVerificationServiceImpl[U: PasskeyUser](
    app: HostApp,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    config: WebAuthnConfig = WebAuthnConfig.default,
    generateChallenge: () => Challenge = () => new DefaultChallenge(),
    clock: Clock = Clock.systemUTC()
)(using ExecutionContext)
    extends PasskeyVerificationService[U] {

  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  private val relyingParty = new PublicKeyCredentialRpEntity(app.host, app.name)

  def buildCreationOptions(user: U): Future[PublicKeyCredentialCreationOptions] =
    for {
      passkeyIds <- passkeyRepo.loadPasskeyIds(user.id)
      challenge = generateChallenge()
      _ <- challengeRepo.insertRegistrationChallenge(user.id, challenge)
    } yield {
      val userInfo = new PublicKeyCredentialUserEntity(user.id.bytes, user.id.value, user.id.value)
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
      user: U,
      passkeyName: String,
      creationResponse: JsValue
  ): Future[CredentialRecord] =
    for {
      // Validate and sanitise the passkey name
      validatedName <- PasskeyName.validate(passkeyName) match
        case Right(name) => Future.successful(name)
        case Left(error) => Future.failed(PasskeyException(PasskeyError.InvalidName(error)))
      // Check for duplicate name (potential race condition - ideally handled at DB level)
      _ <- passkeyRepo
        .loadPasskeyNames(user.id)
        .flatMap(names =>
          if names.contains(validatedName.value) then
            Future.failed(PasskeyException(PasskeyError.DuplicateName(validatedName.value)))
          else Future.successful(())
        )
      challenge <- challengeRepo.loadRegistrationChallenge(user.id)
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
      _ <- passkeyRepo.insertPasskey(user.id, validatedName.value, credentialRecord)
      _ <- challengeRepo.deleteRegistrationChallenge(user.id)
    } yield credentialRecord

  def buildAuthenticationOptions(user: U): Future[PublicKeyCredentialRequestOptions] =
    for {
      passkeyIds <- passkeyRepo.loadPasskeyIds(user.id)
      challenge = generateChallenge()
      _ <- challengeRepo.insertAuthenticationChallenge(user.id, challenge)
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

  def verify(user: U, authenticationResponse: JsValue): Future[AuthenticationData] =
    for {
      challenge <- challengeRepo.loadAuthenticationChallenge(user.id)
      authData <- Future.fromTry(Try(webAuthnManager.parseAuthenticationResponseJSON(authenticationResponse.toString)))
      credentialId = PasskeyId(authData.getCredentialId)
      credentialRecord <- passkeyRepo.loadPasskey(user.id, credentialId)
      verifiedAuthData <- Future.fromTry(
        Try(
          webAuthnManager.verify(
            authData,
            new AuthenticationParameters(
              ServerProperty.builder.origin(app.origin).rpId(app.host).challenge(challenge).build(),
              credentialRecord,
              List(authData.getCredentialId).asJava,
              config.userVerificationRequired
            )
          )
        )
      )
      verifiedCredentialId = PasskeyId(verifiedAuthData.getCredentialId)
      _ <- challengeRepo.deleteAuthenticationChallenge(user.id)
      _ <- passkeyRepo.updateAuthenticationCount(
        user.id,
        verifiedCredentialId,
        verifiedAuthData.getAuthenticatorData.getSignCount
      )
      _ <- passkeyRepo.updateLastUsedTime(user.id, verifiedCredentialId, clock.instant())
    } yield verifiedAuthData

  def listPasskeys(user: U): Future[List[PasskeyInfo]] =
    passkeyRepo.listPasskeys(user.id)

  def deletePasskey(user: U, passkeyId: PasskeyId): Future[Unit] =
    passkeyRepo.deletePasskey(user.id, passkeyId)

  private def toDescriptor(passkeyId: PasskeyId): PublicKeyCredentialDescriptor =
    new PublicKeyCredentialDescriptor(
      config.credentialType,
      passkeyId.bytes,
      config.transports.map(_.asJava).orNull
    )
}
