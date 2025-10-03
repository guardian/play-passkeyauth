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
import com.gu.playpasskeyauth.web.*
import play.api.mvc.{ActionBuilder, AnyContent, Call, ControllerComponents}

import scala.concurrent.ExecutionContext

class PasskeyAuth(
    app: HostApp,
    authAction: AuthAction[AnyContent],
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository
) {
  private val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(app, passkeyRepo, challengeRepo)

  def verificationAction(
      authenticationDataExtractor: AuthenticationDataExtractor
  )(using ExecutionContext): ActionBuilder[RequestWithAuthenticationData, AnyContent] = {
    val authDataAction = new AuthenticationDataAction(authenticationDataExtractor)
    val verificationFilter = new PasskeyVerificationFilter(verificationService)
    authAction.andThen(authDataAction).andThen(verificationFilter)
  }

  def controller(
      controllerComponents: ControllerComponents,
      creationDataExtractor: CreationDataExtractor,
      passkeyNameExtractor: PasskeyNameExtractor,
      registrationRedirect: Call
  )(using ExecutionContext): BasePasskeyController = {
    val creationDataAction = new CreationDataAction(creationDataExtractor, passkeyNameExtractor)
    val userAndCreationDataAction = authAction.andThen(creationDataAction)
    new BasePasskeyController(
      controllerComponents,
      verificationService,
      authAction,
      userAndCreationDataAction,
      registrationRedirect
    )
  }
}
