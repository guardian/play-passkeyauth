package com.gu.playpasskeyauth.services

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data.{AuthenticationData, AuthenticationParameters}
import com.webauthn4j.data.client.Origin
import com.webauthn4j.server.ServerProperty

import java.net.URI
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.jdk.CollectionConverters.*
import scala.util.Try

class Webauthn4jPasskeyVerificationService(
    appHost: String,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository
) extends PasskeyVerificationService:

  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
  private val userVerificationRequired = true

  def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData] =
    for {
      optChallenge <- challengeRepo.loadAuthenticationChallenge(userId)
      challenge <- optChallenge
        .map(c => Future.successful(c))
        .getOrElse(Future.failed(new RuntimeException("Challenge not found")))
      optPasskey <- passkeyRepo.loadPasskey(userId, authData.getCredentialId)
      passkey <- optPasskey
        .map(p => Future.successful(p))
        .getOrElse(Future.failed(new RuntimeException("Passkey not found")))
      serverProps = new ServerProperty(Origin.create(appHost), URI.create(appHost).getHost, challenge)
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
