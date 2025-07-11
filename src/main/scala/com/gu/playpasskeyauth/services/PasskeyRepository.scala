package com.gu.playpasskeyauth.services

import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.AuthenticationData
import com.gu.playpasskeyauth.services.PasskeyAuthFailure.*

trait PasskeyRepository:

  def loadAuthenticationChallenge(userId: String): Either[RepositoryFailure, Option[Challenge]]

  def loadPasskey(userId: String, passkeyId: Array[Byte]): Either[RepositoryFailure, Option[CredentialRecord]]

  def insertPasskey(s: String): Either[RepositoryFailure, Unit]

  def updateAuthenticationCounter(userId: String, authData: AuthenticationData): Either[RepositoryFailure, Unit]

  def updateLastUsedTime(userId: String, authData: AuthenticationData): Either[RepositoryFailure, Unit]

  def deleteAuthenticationChallenge(userId: String): Either[RepositoryFailure, Unit]
