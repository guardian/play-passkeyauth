package modules

import com.google.inject.AbstractModule
import com.gu.playpasskeyauth.PasskeyAuthSimple
import com.gu.playpasskeyauth.models.PasskeyAuthConfig
import com.gu.playpasskeyauth.services.{PasskeyChallengeRepository, PasskeyRepository}
import play.api.{Configuration, Environment}
import services.{InMemoryChallengeRepository, InMemoryPasskeyRepository}

import javax.inject.{Inject, Provider, Singleton}
import scala.concurrent.ExecutionContext

/** Guice module for configuring passkey authentication dependencies. */
class PasskeyModule extends AbstractModule {

  override def configure(): Unit = {
    // Bind repository implementations
    bind(classOf[PasskeyRepository]).to(classOf[InMemoryPasskeyRepository])
    bind(classOf[PasskeyChallengeRepository]).to(classOf[InMemoryChallengeRepository])

    // Bind PasskeyAuthSimple via a provider to inject config
    bind(classOf[PasskeyAuthSimple]).toProvider(classOf[PasskeyAuthProvider])
  }
}

/** Provider for PasskeyAuthSimple that reads configuration from application.conf. */
@Singleton
class PasskeyAuthProvider @Inject() (
    config: Configuration,
    passkeyRepo: PasskeyRepository,
    challengeRepo: PasskeyChallengeRepository,
    ec: ExecutionContext
) extends Provider[PasskeyAuthSimple] {

  override def get(): PasskeyAuthSimple = {
    val appName = config.get[String]("passkey.app.name")
    val appOrigin = config.get[String]("passkey.app.origin")

    val passkeyConfig = PasskeyAuthConfig(
      appName = appName,
      appOrigin = new java.net.URI(appOrigin)
    )

    new PasskeyAuthSimple(passkeyConfig, passkeyRepo, challengeRepo)(using ec)
  }
}
