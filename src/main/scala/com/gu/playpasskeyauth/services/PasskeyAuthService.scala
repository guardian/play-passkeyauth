package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.services.PasskeyRepository
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data.{AuthenticationData, AuthenticationParameters}
import com.webauthn4j.data.client.Origin
import com.webauthn4j.server.ServerProperty

import java.net.URI
import scala.jdk.CollectionConverters.*
import scala.util.Try

trait PasskeyAuthService:
  def verify(userId: String, authData: AuthenticationData): Either[PasskeyAuthFailure, AuthenticationData]
