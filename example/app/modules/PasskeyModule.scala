package modules

import com.google.inject.{AbstractModule, Provides}
import com.gu.playpasskeyauth.models.{HostApp, WebAuthnConfig, User as PasskeyUser}
import com.gu.playpasskeyauth.services.{PasskeyChallengeRepository, PasskeyRepository}
import com.gu.playpasskeyauth.web.*
import com.gu.playpasskeyauth.{PasskeyAuth, PasskeyAuthContext}
import models.User
import play.api.Configuration
import play.api.libs.json.JsValue
import play.api.mvc.{AnyContent, DefaultActionBuilder, Request}
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
    given ecImplicit: ExecutionContext = ec
    val appName = config.get[String]("passkey.app.name")
    val appOrigin = config.get[String]("passkey.app.origin")

    val hostApp = HostApp(appName, new java.net.URI(appOrigin))

    // Extractors to get data from a request
    val userExtractor = new UserExtractor[User, [A] =>> Request[A]] {
      def extractUser[A](request: Request[A]): User = User.demo
    }

    val creationDataExtractor = new CreationDataExtractor[[A] =>> RequestWithUser[User, A]] {
      def findCreationData[A](request: RequestWithUser[User, A]): Option[JsValue] =
        request.body match {
          case body: AnyContent => body.asJson.flatMap(json => (json \ "credential").asOpt[JsValue])
          case _                => None
        }
    }

    val authDataExtractor = new AuthenticationDataExtractor[[A] =>> RequestWithUser[User, A]] {
      def findAuthenticationData[A](request: RequestWithUser[User, A]): Option[JsValue] =
        request.body match {
          case body: AnyContent => body.asJson.flatMap(json => (json \ "assertion").asOpt[JsValue])
          case _                => None
        }
    }

    val passkeyNameExtractor = new PasskeyNameExtractor[[A] =>> RequestWithUser[User, A]] {
      def findPasskeyName[A](request: RequestWithUser[User, A]): Option[String] =
        request.body match {
          case body: AnyContent => body.asJson.flatMap(json => (json \ "name").asOpt[String])
          case _                => None
        }
    }

    // Create the context bundling everything together
    val passKeyAuthContext: PasskeyAuthContext[User, AnyContent] = PasskeyAuthContext(
      userAction = DefaultActionBuilder(cc.parsers.default).andThen(new UserAction(userExtractor)),
      creationDataExtractor = creationDataExtractor,
      authenticationDataExtractor = authDataExtractor,
      passkeyNameExtractor = passkeyNameExtractor,
      webAuthnConfig = WebAuthnConfig.default
    )

    // Ensure the User typeclass is in implicit scope for the PasskeyAuth constructor
    given PasskeyUser[User] = models.User.given_PasskeyUser_User

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
