package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.controllers.BasePasskeyController
import com.gu.playpasskeyauth.filters.PasskeyVerificationFilter
import com.gu.playpasskeyauth.models.HostApp
import com.gu.playpasskeyauth.services.{PasskeyChallengeRepository, PasskeyRepository, PasskeyVerificationService, PasskeyVerificationServiceImpl}
import com.gu.playpasskeyauth.web.RequestExtractor
import play.api.mvc.{ActionBuilder, AnyContent, ControllerComponents}

import scala.concurrent.ExecutionContext

class Passkey(app: HostApp, passkeyRepo: PasskeyRepository, challengeRepo: PasskeyChallengeRepository) {

  private val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(app, passkeyRepo, challengeRepo)

  def verificationFilter[R[_]]()(using RequestExtractor[R], ExecutionContext): PasskeyVerificationFilter[R] =
    new PasskeyVerificationFilter[R](verificationService)
}
