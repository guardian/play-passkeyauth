package com.gu.playpasskeyauth.services

import com.webauthn4j.data.AuthenticationData
import com.gu.playpasskeyauth.services.PasskeyRepository
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.data.client.Origin
import java.net.URI
import scala.jdk.CollectionConverters.*
import com.webauthn4j.WebAuthnManager
import scala.util.Try
import com.gu.playpasskeyauth.services.PasskeyAuthFailure.*

class Webauthn4jPasskeyAuthService(appHost: String, repo: PasskeyRepository) extends PasskeyAuthService:

  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
  private val userVerificationRequired = true

  def verify(userId: String, authData: AuthenticationData): Either[PasskeyAuthFailure, AuthenticationData] =
    for {
      optChallenge <- repo.loadAuthenticationChallenge(userId)
      challenge <- optChallenge.toRight(NotFoundFailure("TODO"))
      optPasskey <- repo.loadPasskey(userId, authData.getCredentialId)
      passkey <- optPasskey.toRight(NotFoundFailure("TODO"))
      serverProps = new ServerProperty(Origin.create(appHost), URI.create(appHost).getHost, challenge)
      authParams = new AuthenticationParameters(
        serverProps,
        passkey,
        List(authData.getCredentialId).asJava,
        userVerificationRequired
      )
      verifiedAuthData <- Try(webAuthnManager.verify(authData, authParams)).toEither.left.map(err =>
        VerificationFailure(err.getMessage)
      )
      _ <- repo.deleteAuthenticationChallenge(userId)
      _ <- repo.updateAuthenticationCounter(userId, verifiedAuthData)
      _ <- repo.updateLastUsedTime(userId, verifiedAuthData)
    } yield verifiedAuthData
