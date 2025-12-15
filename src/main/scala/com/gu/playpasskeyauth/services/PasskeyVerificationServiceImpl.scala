package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.{HostApp, PasskeyName, PasskeyUser, WebAuthnConfig}
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.{CredentialRecord, CredentialRecordImpl}
import com.webauthn4j.data.*
import com.webauthn4j.data.client.challenge.{Challenge, DefaultChallenge}
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.util.Base64UrlUtil
import play.api.libs.json.JsValue

import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters.*
import scala.util.Try

private[playpasskeyauth] class PasskeyVerificationServiceImpl[U: PasskeyUser](
    app: HostApp,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    config: WebAuthnConfig = WebAuthnConfig.default,
    generateChallenge: () => Challenge = () => new DefaultChallenge()
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
      val userInfo = new PublicKeyCredentialUserEntity(user.id.getBytes(UTF_8), user.id, user.id)
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
      // There's a potential race condition here if another request conflicts with it so would be better at DB level - but leaving it here for now
      _ <- passkeyRepo
        .loadPasskeyNames(user.id)
        .flatMap(names => {
          if (names.contains(validatedName.value)) {
            Future
              .failed(PasskeyException(PasskeyError.DuplicateName(validatedName.value)))
          } else {
            Future.successful(())
          }
        })
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
      credentialRecord <- passkeyRepo.loadPasskey(user.id, authData.getCredentialId)
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
      _ <- challengeRepo.deleteAuthenticationChallenge(user.id)
      _ <- passkeyRepo.updateAuthenticationCount(
        user.id,
        verifiedAuthData.getCredentialId,
        verifiedAuthData.getAuthenticatorData.getSignCount
      )
      _ <- passkeyRepo.updateLastUsedTime(user.id, verifiedAuthData.getCredentialId, Instant.now())
    } yield verifiedAuthData

  private def toDescriptor(passkeyId: String): PublicKeyCredentialDescriptor =
    new PublicKeyCredentialDescriptor(
      config.credentialType,
      Base64UrlUtil.decode(passkeyId),
      config.transports.map(_.asJava).orNull
    )
}
