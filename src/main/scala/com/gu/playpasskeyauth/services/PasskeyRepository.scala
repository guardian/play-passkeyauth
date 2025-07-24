package com.gu.playpasskeyauth.services

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.AuthenticationData

import scala.concurrent.Future

trait PasskeyRepository {

  def loadCredentialRecord(userId: String, passkeyId: Array[Byte]): Future[Option[CredentialRecord]]

  def loadPasskeyIds(userId: String): Future[List[String]]

  def updateAuthenticationCounter(userId: String, authData: AuthenticationData): Future[Unit]

  def updateLastUsedTime(userId: String, authData: AuthenticationData): Future[Unit]
}
