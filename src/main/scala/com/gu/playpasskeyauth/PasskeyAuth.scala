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
    controllerComponents: ControllerComponents,
    app: HostApp,
    authAction: AuthAction[AnyContent],
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    creationDataExtractor: CreationDataExtractor,
    authenticationDataExtractor: AuthenticationDataExtractor,
    passkeyNameExtractor: PasskeyNameExtractor,
    registrationRedirect: Call
)(using ExecutionContext) {
  private val verificationService: PasskeyVerificationService =
    new PasskeyVerificationServiceImpl(app, passkeyRepo, challengeRepo)

  def verificationAction(): ActionBuilder[RequestWithAuthenticationData, AnyContent] = {
    val authDataAction = new AuthenticationDataAction(authenticationDataExtractor)
    val verificationFilter = new PasskeyVerificationFilter(verificationService)
    authAction.andThen(authDataAction).andThen(verificationFilter)
  }

  def controller(): BasePasskeyController = {
    val verificationFilter = new PasskeyVerificationFilter(verificationService)
    val creationDataAction = new CreationDataAction(creationDataExtractor, passkeyNameExtractor)
    val authDataAction = new AuthenticationDataAction(authenticationDataExtractor)
    val userAndCreationDataAction = authAction.andThen(creationDataAction)
    val userAndDeletionDataAction =
      authAction.andThen(authDataAction).andThen(verificationFilter)
    new BasePasskeyController(
      controllerComponents,
      verificationService,
      authAction,
      userAndCreationDataAction,
      userAndDeletionDataAction,
      registrationRedirect
    )
  }
}
