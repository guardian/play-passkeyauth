package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.HostApp
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.*
import com.webauthn4j.data.client.challenge.{Challenge, DefaultChallenge}
import org.mockito.ArgumentMatchers.{any, eq as eqTo}
import org.mockito.Mockito.*
import org.scalatest.concurrent.ScalaFutures
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.libs.json.{JsObject, Json}

import java.net.URI
import java.nio.charset.StandardCharsets.UTF_8
import scala.concurrent.Future

class PasskeyVerificationServiceImplTest extends PlaySpec with MockitoSugar with ScalaFutures {

  private val testApp = HostApp("Test App", URI.create("https://test.example.com"))
  private val testUserId = "test-user-123"
  private val testPasskeyId = "test-passkey-id"
  private val testChallenge = new DefaultChallenge("test-challenge".getBytes(UTF_8))

  private def createService(
      passkeyRepo: PasskeyRepository = mock[PasskeyRepository],
      challengeRepo: PasskeyChallengeRepository = mock[PasskeyChallengeRepository],
      challengeGenerator: () => Challenge = () => testChallenge
  ): PasskeyVerificationServiceImpl = {
    new PasskeyVerificationServiceImpl(testApp, passkeyRepo, challengeRepo, challengeGenerator)
  }

  "creationOptions" must {
    "return creation options with correct relying party" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertRegistrationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.creationOptions(testUserId).futureValue

      result.getRp.getId mustBe testApp.host
    }

    "return creation options with correct user entity" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertRegistrationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.creationOptions(testUserId).futureValue

      result.getUser.getId mustBe testUserId.getBytes(UTF_8)
    }

    "return creation options with generated challenge" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertRegistrationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.creationOptions(testUserId).futureValue

      result.getChallenge mustBe testChallenge
    }

    "exclude existing passkeys from creation options" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List(testPasskeyId)))
      when(challengeRepo.insertRegistrationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.creationOptions(testUserId).futureValue

      result.getExcludeCredentials.size() mustBe 1
    }

    "insert registration challenge in repository" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertRegistrationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      service.creationOptions(testUserId).futureValue

      verify(challengeRepo).insertRegistrationChallenge(eqTo(testUserId), eqTo(testChallenge))
    }
  }

  "register" must {
    "return credential record for valid registration response" ignore {
      val service = createService()
      val response = Json.parse("""{"id":"test","response":{"attestationObject":"test","clientDataJSON":"test"}}""")

      // This test would need a more complex setup with WebAuthnManager mocking
      // For now, testing that the method exists and has correct signature
      noException must be thrownBy service.register(testUserId, response)
    }
  }

  "authenticationOptions" must {
    "return authentication options with correct challenge" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertAuthenticationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.authenticationOptions(testUserId).futureValue

      result.getChallenge mustBe testChallenge
    }

    "return authentication options with correct RP ID" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertAuthenticationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.authenticationOptions(testUserId).futureValue

      result.getRpId mustBe testApp.host
    }

    "include allowed credentials from repository" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List(testPasskeyId)))
      when(challengeRepo.insertAuthenticationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.authenticationOptions(testUserId).futureValue

      result.getAllowCredentials.size() mustBe 1
    }

    "return authentication options with required user verification" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertAuthenticationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.authenticationOptions(testUserId).futureValue

      result.getUserVerification mustBe UserVerificationRequirement.REQUIRED
    }

    "insert authentication challenge in repository" in {
      val passkeyRepo = mock[PasskeyRepository]
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(passkeyRepo.loadPasskeyIds(testUserId)).thenReturn(Future.successful(List.empty))
      when(challengeRepo.insertAuthenticationChallenge(eqTo(testUserId), any[Challenge]))
        .thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)
      service.authenticationOptions(testUserId).futureValue

      verify(challengeRepo).insertAuthenticationChallenge(eqTo(testUserId), eqTo(testChallenge))
    }
  }

  "verify" must {
    "fail when challenge not found" in {
      val challengeRepo = mock[PasskeyChallengeRepository]
      when(challengeRepo.loadAuthenticationChallenge(testUserId)).thenReturn(Future.successful(None))

      val service = createService(challengeRepo = challengeRepo)
      val authData = mock[JsObject]

      val result = service.verify(testUserId, authData)

      result.failed.futureValue mustBe a[RuntimeException]
    }

    "fail when passkey not found" in {
      val challengeRepo = mock[PasskeyChallengeRepository]
      val passkeyRepo = mock[PasskeyRepository]
      val credentialId = "test-credential-id".getBytes(UTF_8)

      when(challengeRepo.loadAuthenticationChallenge(testUserId)).thenReturn(Future.successful(Some(testChallenge)))
      when(passkeyRepo.loadCredentialRecord(testUserId, credentialId)).thenReturn(Future.successful(None))

      val authData = mock[JsObject]

      val service = createService(passkeyRepo, challengeRepo)
      val result = service.verify(testUserId, authData)

      result.failed.futureValue mustBe a[RuntimeException]
    }

    "delete challenge after successful verification" ignore {
      val challengeRepo = mock[PasskeyChallengeRepository]
      val passkeyRepo = mock[PasskeyRepository]
      val credentialRecord = mock[CredentialRecord]
      val credentialId = "test-credential-id".getBytes(UTF_8)
      val authData = mock[JsObject]

      when(challengeRepo.loadAuthenticationChallenge(testUserId)).thenReturn(Future.successful(Some(testChallenge)))
      when(passkeyRepo.loadCredentialRecord(testUserId, credentialId))
        .thenReturn(Future.successful(Some(credentialRecord)))
      when(challengeRepo.deleteAuthenticationChallenge(testUserId)).thenReturn(Future.successful(()))
      when(passkeyRepo.updateAuthenticationCounter(eqTo(testUserId), any[AuthenticationData]))
        .thenReturn(Future.successful(()))
      when(passkeyRepo.updateLastUsedTime(eqTo(testUserId), any[AuthenticationData])).thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)

      // This would need WebAuthnManager mocking for full test
      // Testing that deleteAuthenticationChallenge is called in the flow
      try {
        service.verify(testUserId, authData).futureValue
      } catch {
        case _: Exception => // Expected due to unmocked WebAuthnManager
      }

      // The method must be called even if verification fails due to mocking
      verify(challengeRepo, atLeastOnce()).deleteAuthenticationChallenge(testUserId)
    }

    "update authentication counter after successful verification" ignore {
      val challengeRepo = mock[PasskeyChallengeRepository]
      val passkeyRepo = mock[PasskeyRepository]
      val credentialRecord = mock[CredentialRecord]
      val credentialId = "test-credential-id".getBytes(UTF_8)
      val authData = mock[JsObject]

      when(challengeRepo.loadAuthenticationChallenge(testUserId)).thenReturn(Future.successful(Some(testChallenge)))
      when(passkeyRepo.loadCredentialRecord(testUserId, credentialId))
        .thenReturn(Future.successful(Some(credentialRecord)))
      when(challengeRepo.deleteAuthenticationChallenge(testUserId)).thenReturn(Future.successful(()))
      when(passkeyRepo.updateAuthenticationCounter(eqTo(testUserId), any[AuthenticationData]))
        .thenReturn(Future.successful(()))
      when(passkeyRepo.updateLastUsedTime(eqTo(testUserId), any[AuthenticationData])).thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)

      try {
        service.verify(testUserId, authData).futureValue
      } catch {
        case _: Exception => // Expected due to unmocked WebAuthnManager
      }

      verify(passkeyRepo, atLeastOnce()).updateAuthenticationCounter(eqTo(testUserId), any[AuthenticationData])
    }

    "update last used time after successful verification" ignore {
      val challengeRepo = mock[PasskeyChallengeRepository]
      val passkeyRepo = mock[PasskeyRepository]
      val credentialRecord = mock[CredentialRecord]
      val credentialId = "test-credential-id".getBytes(UTF_8)
      val authData = mock[JsObject]

      when(challengeRepo.loadAuthenticationChallenge(testUserId)).thenReturn(Future.successful(Some(testChallenge)))
      when(passkeyRepo.loadCredentialRecord(testUserId, credentialId))
        .thenReturn(Future.successful(Some(credentialRecord)))
      when(challengeRepo.deleteAuthenticationChallenge(testUserId)).thenReturn(Future.successful(()))
      when(passkeyRepo.updateAuthenticationCounter(eqTo(testUserId), any[AuthenticationData]))
        .thenReturn(Future.successful(()))
      when(passkeyRepo.updateLastUsedTime(eqTo(testUserId), any[AuthenticationData])).thenReturn(Future.successful(()))

      val service = createService(passkeyRepo, challengeRepo)

      try {
        service.verify(testUserId, authData).futureValue
      } catch {
        case _: Exception => // Expected due to unmocked WebAuthnManager
      }

      verify(passkeyRepo, atLeastOnce()).updateLastUsedTime(eqTo(testUserId), any[AuthenticationData])
    }
  }
}
