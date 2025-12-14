package com.gu.playpasskeyauth

import com.gu.playpasskeyauth.controllers.BasePasskeyController
import com.gu.playpasskeyauth.filters.PasskeyVerificationFilter
import com.gu.playpasskeyauth.models.{HostApp, PasskeyUser}
import com.gu.playpasskeyauth.services.{
  PasskeyChallengeRepository,
  PasskeyRepository,
  PasskeyVerificationService,
  PasskeyVerificationServiceImpl
}
import com.gu.playpasskeyauth.web.*
import play.api.mvc.{ActionBuilder, AnyContent, Call, ControllerComponents, Request}

import scala.concurrent.ExecutionContext

class PasskeyAuth[U: PasskeyUser, R[A] <: Request[A]](
    controllerComponents: ControllerComponents,
    app: HostApp,
    authAction: ActionBuilder[R, AnyContent],
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    userExtractor: UserExtractor[U, R],
    creationDataExtractor: CreationDataExtractor[[A] =>> RequestWithUser[U, A]],
    authenticationDataExtractor: AuthenticationDataExtractor[[A] =>> RequestWithUser[U, A]],
    passkeyNameExtractor: PasskeyNameExtractor[[A] =>> RequestWithUser[U, A]],
    registrationRedirect: Call
)(using ExecutionContext) {
  private val verificationService: PasskeyVerificationService[U] =
    new PasskeyVerificationServiceImpl[U](app, passkeyRepo, challengeRepo)

  private val userAction: ActionBuilder[[A] =>> RequestWithUser[U, A], AnyContent] =
    authAction.andThen(new UserAction[U, R](userExtractor))

  def verificationAction(): ActionBuilder[[A] =>> RequestWithAuthenticationData[U, A], AnyContent] = {
    val authDataAction = new AuthenticationDataAction[U](authenticationDataExtractor)
    val verificationFilter = new PasskeyVerificationFilter[U](verificationService)
    userAction.andThen(authDataAction).andThen(verificationFilter)
  }

  def controller(): BasePasskeyController[U] = {
    val verificationFilter = new PasskeyVerificationFilter[U](verificationService)
    val creationDataAction = new CreationDataAction[U](creationDataExtractor, passkeyNameExtractor)
    val userAndCreationDataAction = userAction.andThen(creationDataAction)
    new BasePasskeyController[U](
      controllerComponents,
      verificationService,
      userAction,
      userAndCreationDataAction,
      registrationRedirect
    )
  }
}
