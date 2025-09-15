package com.gu.playpasskeyauth

import com.gu.googleauth.AuthAction
import com.gu.playpasskeyauth.controllers.BasePasskeyController
import com.gu.playpasskeyauth.filters.PasskeyVerificationFilter
import com.gu.playpasskeyauth.models.HostApp
import com.gu.playpasskeyauth.services.{
  PasskeyChallengeRepository,
  PasskeyRepository,
  PasskeyVerificationService,
  PasskeyVerificationServiceImpl
}
import com.gu.playpasskeyauth.web.RequestWithCreationData
import play.api.mvc.{ActionBuilder, AnyContent, ControllerComponents}

import scala.concurrent.ExecutionContext

class PasskeyAuth(
    app: HostApp,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository
) {

  private val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(app, passkeyRepo, challengeRepo)

  def verificationFilter(using ExecutionContext): PasskeyVerificationFilter =
    new PasskeyVerificationFilter(verificationService)

  def controller(
      controllerComponents: ControllerComponents,
      authAction: AuthAction[AnyContent],
      userAndCreationDataAction: ActionBuilder[RequestWithCreationData, AnyContent]
  )(using ExecutionContext): BasePasskeyController =
    new BasePasskeyController(controllerComponents, verificationService, authAction, userAndCreationDataAction)
}
