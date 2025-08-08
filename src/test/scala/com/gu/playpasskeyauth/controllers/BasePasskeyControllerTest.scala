package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestExtractor
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.challenge.DefaultChallenge
import org.apache.pekko.stream.Materializer
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.*
import org.scalatest.concurrent.ScalaFutures
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.*
import play.api.libs.json.Json
import play.api.mvc.*
import play.api.test.Helpers.*
import play.api.test.{FakeRequest, Helpers}

import scala.concurrent.{ExecutionContext, Future}

class BasePasskeyControllerTest extends PlaySpec with MockitoSugar with ScalaFutures {

  given ExecutionContext = ExecutionContext.global
  given Materializer = Materializer.matFromSystem(
    org.apache.pekko.actor.ActorSystem("silent-test-system")
  )

  private val testUserId = "user123"
  private val testCreationResponse = Json.parse("""{"id":"test","response":{"clientDataJSON":"test"}}""")

  private def createTestCreationOptions(): PublicKeyCredentialCreationOptions = {
    val rp = new PublicKeyCredentialRpEntity("example.com", "Test App")
    val user = new PublicKeyCredentialUserEntity(testUserId.getBytes, "testuser", "Test User")
    val challenge = new DefaultChallenge("test-challenge".getBytes)
    val pubKeyCredParams = java.util.List.of(
      new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
    )
    new PublicKeyCredentialCreationOptions(rp, user, challenge, pubKeyCredParams, null, null, null, null, null)
  }

  private def createTestRequestOptions(): PublicKeyCredentialRequestOptions = {
    val challenge = new DefaultChallenge("auth-challenge".getBytes)
    new PublicKeyCredentialRequestOptions(challenge, null, "example.com", null, null, null)
  }

  // Concrete implementation of BasePasskeyController for testing
  class TestPasskeyController(
      controllerComponents: ControllerComponents,
      customAction: ActionBuilder[Request, AnyContent],
      service: PasskeyVerificationService
  )(using RequestExtractor: RequestExtractor[Request], ec: ExecutionContext)
      extends BasePasskeyController[Request](controllerComponents, customAction, service)

  private def createController(
      RequestExtractor: RequestExtractor[Request] = mock[RequestExtractor[Request]],
      service: PasskeyVerificationService = mock[PasskeyVerificationService]
  ): TestPasskeyController = {
    val controllerComponents = Helpers.stubControllerComponents()
    val customAction = controllerComponents.actionBuilder
    new TestPasskeyController(controllerComponents, customAction, service)(using RequestExtractor)
  }

  "creationOptions" should {

    "return 200 OK on success" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      status(result) mustBe OK
    }

    "return JSON content type on success" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      contentType(result) mustBe Some("application/json")
    }

    "return valid JSON response body" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      val jsonBody = contentAsJson(result)
      jsonBody must not be null
    }

    "include rp field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "rp").get.toString mustEqual """{"id":"example.com","name":"Test App"}"""
    }

    "include user field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "user").get.toString mustEqual """{"id":"dXNlcjEyMw","name":"testuser","displayName":"Test User"}"""
    }

    "include challenge field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "challenge").as[String] mustEqual "dGVzdC1jaGFsbGVuZ2U"
    }

    "include pubKeyCredParams field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.successful(createTestCreationOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "pubKeyCredParams").get.toString mustEqual """[{"type":"public-key","alg":-7}]"""
    }

    "return 400 Bad Request when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.failed(new RuntimeException("Service error")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.failed(new RuntimeException("Service error")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.creationOptions(testUserId)).thenReturn(Future.failed(new IllegalArgumentException("Invalid user")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)

      status(result) mustBe BAD_REQUEST
    }
  }

  "register" should {

    "return 204 No Content on success" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      val credentialRecord = mock[CredentialRecord]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(Some(testCreationResponse))
      when(service.register(testUserId, testCreationResponse)).thenReturn(Future.successful(credentialRecord))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      status(result) mustBe NO_CONTENT
    }

    "return 400 Bad Request when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request when creation data is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      status(result) mustBe BAD_REQUEST
    }

    "return error message when creation data is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(Some(testCreationResponse))
      when(service.register(testUserId, testCreationResponse))
        .thenReturn(Future.failed(new RuntimeException("Registration failed")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(Some(testCreationResponse))
      when(service.register(testUserId, testCreationResponse))
        .thenReturn(Future.failed(new RuntimeException("Registration failed")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(RequestExtractor.findCreationData(any())).thenReturn(Some(testCreationResponse))
      when(service.register(testUserId, testCreationResponse))
        .thenReturn(Future.failed(new IllegalArgumentException("Invalid registration data")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)

      status(result) mustBe BAD_REQUEST
    }
  }

  "authenticationOptions" should {

    "return 200 OK on success" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId)).thenReturn(Future.successful(createTestRequestOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      status(result) mustBe OK
    }

    "return JSON content type on success" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId)).thenReturn(Future.successful(createTestRequestOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      contentType(result) mustBe Some("application/json")
    }

    "return valid JSON response body" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId)).thenReturn(Future.successful(createTestRequestOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      val jsonBody = contentAsJson(result)
      jsonBody must not be null
    }

    "include challenge field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId)).thenReturn(Future.successful(createTestRequestOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "challenge").as[String] mustEqual "YXV0aC1jaGFsbGVuZ2U"
    }

    "include rpId field in JSON response" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId)).thenReturn(Future.successful(createTestRequestOptions()))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      val jsonBody = contentAsJson(result)
      (jsonBody \ "rpId").as[String] mustEqual "example.com"
    }

    "return 400 Bad Request when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      when(RequestExtractor.findUserId(any())).thenReturn(None)

      val controller = createController(RequestExtractor)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId))
        .thenReturn(Future.failed(new RuntimeException("Auth options failed")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId))
        .thenReturn(Future.failed(new RuntimeException("Auth options failed")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val service = mock[PasskeyVerificationService]
      when(RequestExtractor.findUserId(any())).thenReturn(Some(testUserId))
      when(service.authenticationOptions(testUserId))
        .thenReturn(Future.failed(new IllegalArgumentException("Invalid auth request")))

      val controller = createController(RequestExtractor, service)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)

      status(result) mustBe BAD_REQUEST
    }
  }
}
