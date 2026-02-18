package modules

import com.google.inject.{AbstractModule, Provides}
import com.gu.playpasskeyauth.models.{HostApp, WebAuthnConfig, User as PasskeyUser}
import com.gu.playpasskeyauth.services.{PasskeyChallengeRepository, PasskeyRepository}
import com.gu.playpasskeyauth.web.*
import com.gu.playpasskeyauth.{PasskeyAuth, PasskeyAuthContext}
import models.User
import play.api.Configuration
import play.api.libs.json.JsValue
import play.api.mvc.{ActionBuilder, AnyContent, DefaultActionBuilder, Request}
import services.{InMemoryChallengeRepository, InMemoryPasskeyRepository}

import javax.inject.Singleton
import scala.concurrent.ExecutionContext

/** Guice module for configuring passkey authentication dependencies. */
class PasskeyModule extends AbstractModule {

  override def configure(): Unit = {
    // Bind repository implementations
    bind(classOf[PasskeyRepository]).to(classOf[InMemoryPasskeyRepository])
    bind(classOf[PasskeyChallengeRepository]).to(classOf[InMemoryChallengeRepository])
  }

  /** Provides a configured PasskeyAuth instance. */
  @Provides
  @Singleton
  def providePasskeyAuth(
      config: Configuration,
      cc: play.api.mvc.ControllerComponents,
      passkeyRepo: PasskeyRepository,
      challengeRepo: PasskeyChallengeRepository,
      ec: ExecutionContext
  ): PasskeyAuth[User, AnyContent] = {
    // Make ExecutionContext and User typeclass available implicitly
    implicit val ecImplicit: ExecutionContext = ec
    val userTypeClass: PasskeyUser[User] = models.User.given_PasskeyUser_User

    val appName = config.get[String]("passkey.app.name")
    val appOrigin = config.get[String]("passkey.app.origin")

    val hostApp = HostApp(appName, new java.net.URI(appOrigin))

    // Create user action that extracts the demo user from requests
    given UserExtractor[User, [A] =>> Request[A]] with {
      def extractUser[A](request: Request[A]): User = User.demo
    }

    // Compose default action builder with UserAction
    val defaultAction = DefaultActionBuilder(cc.parsers.default)
    val userAction: ActionBuilder[[A] =>> RequestWithUser[User, A], AnyContent] =
      defaultAction.andThen(new UserAction(summon[UserExtractor[User, [A] =>> Request[A]]]))

    // Create extractors for creation and authentication data
    given CreationDataExtractor[[A] =>> RequestWithUser[User, A]] with {
      def findCreationData[A](request: RequestWithUser[User, A]): Option[JsValue] = {
        request.body match {
          case body: AnyContent =>
            body.asJson.flatMap(json => (json \ "credential").asOpt[JsValue])
          case _ => None
        }
      }
    }

    given AuthenticationDataExtractor[[A] =>> RequestWithUser[User, A]] with {
      def findAuthenticationData[A](request: RequestWithUser[User, A]): Option[JsValue] = {
        request.body match {
          case body: AnyContent =>
            body.asJson.flatMap(json => (json \ "assertion").asOpt[JsValue])
          case _ => None
        }
      }
    }

    given PasskeyNameExtractor[[A] =>> RequestWithUser[User, A]] with {
      def findPasskeyName[A](request: RequestWithUser[User, A]): Option[String] = {
        request.body match {
          case body: AnyContent =>
            body.asJson.flatMap(json => (json \ "name").asOpt[String])
          case _ => None
        }
      }
    }

    // Create the context bundling everything together
    val passKeyAuthContext: PasskeyAuthContext[User, AnyContent] = PasskeyAuthContext(
      userAction = userAction,
      creationDataExtractor = summon,
      authenticationDataExtractor = summon,
      passkeyNameExtractor = summon,
      webAuthnConfig = WebAuthnConfig.default
    )

    // Ensure the User typeclass is in implicit scope for the PasskeyAuth constructor
    given PasskeyUser[User] = userTypeClass

    new PasskeyAuth(
      cc,
      hostApp,
      passKeyAuthContext,
      passkeyRepo,
      challengeRepo,
      play.api.mvc.Call("GET", "/")
    )
  }
}
