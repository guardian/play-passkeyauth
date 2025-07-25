package com.gu.playpasskeyauth.services

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.AuthenticationData
import com.webauthn4j.data.client.challenge.Challenge

import scala.concurrent.Future

trait PasskeyChallengeRepository {

  def loadRegistrationChallenge(userId: String): Future[Option[Challenge]]

  def insertRegistrationChallenge(userId: String, challenge: Challenge): Future[Unit]

  def deleteRegistrationChallenge(userId: String): Future[Unit]

  def loadAuthenticationChallenge(userId: String): Future[Option[Challenge]]

  def insertAuthenticationChallenge(userId: String, challenge: Challenge): Future[Unit]

  def deleteAuthenticationChallenge(userId: String): Future[Unit]
}
