package modules

import com.google.inject.{AbstractModule, Provides}
import com.gu.playpasskeyauth.models.{HostApp, PasskeyUser, WebAuthnConfig}
import com.gu.playpasskeyauth.services.{PasskeyChallengeRepository, PasskeyRepository}
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

    // Ensure the PasskeyUser typeclass is in implicit scope for the PasskeyAuth constructor
    given PasskeyUser[User] = User.given_PasskeyUser_User

    val ctx = PasskeyAuthContext[User, AnyContent](
      actionBuilder = DefaultActionBuilder(cc.parsers.default),
      userExtractor = _ => User.demo,
      creationDataExtractor = req =>
        req.body match {
          case body: AnyContent => body.asJson.flatMap(j => (j \ "credential").asOpt[JsValue])
          case _                => None
        },
      authenticationDataExtractor = req =>
        req.body match {
          case body: AnyContent => body.asJson.flatMap(j => (j \ "assertion").asOpt[JsValue])
          case _                => None
        },
      passkeyNameExtractor = req =>
        req.body match {
          case body: AnyContent => body.asJson.flatMap(j => (j \ "name").asOpt[String])
          case _                => None
        }
    )

    new PasskeyAuth(cc, hostApp, ctx, passkeyRepo, challengeRepo, play.api.mvc.Call("GET", "/"))
  }
}
