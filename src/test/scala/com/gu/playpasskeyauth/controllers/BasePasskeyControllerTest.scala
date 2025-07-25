package com.gu.playpasskeyauth.controllers

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestHelper
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.data.client.CollectedClientData
import org.apache.pekko.stream.Materializer
import org.scalatestplus.play.*
import play.api.libs.json.JsValue
import play.api.mvc.*
import play.api.test.Helpers.*
import play.api.test.{FakeRequest, Helpers}

import java.lang
import scala.concurrent.{ExecutionContext, Future}

class BasePasskeyControllerTest extends PlaySpec {

  given ExecutionContext = ExecutionContext.global
  given Materializer = Materializer.matFromSystem(
    org.apache.pekko.actor.ActorSystem("silent-test-system")
  )

  private val testUserId = "user123"
  private val testJsonCreationResponse = """{"id":"test","response":{"clientDataJSON":"test"}}"""

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

  private def createTestCredentialRecord(): CredentialRecord = {
    new CredentialRecord {
      def getClientData: CollectedClientData = ???
      def isUvInitialized: lang.Boolean = ???
      def setUvInitialized(value: Boolean): Unit = ???
      def isBackupEligible: lang.Boolean = ???
      def setBackupEligible(Boolean: Boolean): Unit = ???
      def isBackedUp: lang.Boolean = ???
      def setBackedUp(value: Boolean): Unit = ???
      def getAttestedCredentialData: AttestedCredentialData = ???
      def getCounter: Long = ???
      def setCounter(value: Long): Unit = ???
    }
  }

  // Mock implementations
  class MockRequestHelper extends RequestHelper[Request] {
    var mockUserId: Option[String] = Some(testUserId)
    var mockCreationData: Option[String] = Some(testJsonCreationResponse)
    var mockAuthData: Option[AuthenticationData] = None

    override def findUserId[A](request: Request[A]): Option[String] = mockUserId
    override def findCreationData[A](request: Request[A]): Option[String] = mockCreationData
    override def findAuthenticationData[A](request: Request[A]): Option[AuthenticationData] = mockAuthData
  }

  class MockPasskeyVerificationService extends PasskeyVerificationService {
    var creationOptionsResult: Future[PublicKeyCredentialCreationOptions] =
      Future.successful(createTestCreationOptions())
    var registerResult: Future[CredentialRecord] = Future.successful(createTestCredentialRecord())
    var authenticationOptionsResult: Future[PublicKeyCredentialRequestOptions] =
      Future.successful(createTestRequestOptions())

    override def creationOptions(userId: String): Future[PublicKeyCredentialCreationOptions] = creationOptionsResult
    override def register(userId: String, jsonCreationResponse: String): Future[CredentialRecord] = registerResult
    override def authenticationOptions(userId: String): Future[PublicKeyCredentialRequestOptions] =
      authenticationOptionsResult
    override def verify(userId: String, authData: AuthenticationData): Future[AuthenticationData] =
      Future.successful(authData)
  }

  // Concrete implementation of BasePasskeyController for testing
  class TestPasskeyController(
      controllerComponents: ControllerComponents,
      customAction: ActionBuilder[Request, AnyContent],
      mockService: MockPasskeyVerificationService
  )(using mockReqHelper: MockRequestHelper, ec: ExecutionContext)
      extends BasePasskeyController[Request](controllerComponents, customAction, mockService)

  private def createController(
      mockReqHelper: MockRequestHelper = new MockRequestHelper(),
      mockService: MockPasskeyVerificationService = new MockPasskeyVerificationService()
  ): TestPasskeyController = {
    val controllerComponents = Helpers.stubControllerComponents()
    val customAction = controllerComponents.actionBuilder
    new TestPasskeyController(controllerComponents, customAction, mockService)(using mockReqHelper)
  }

  "creationOptions" should {

    "return 200 OK on success" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      status(result) mustBe OK
    }

    "return JSON content type on success" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      contentType(result) mustBe Some("application/json")
    }

    "return valid JSON response body" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      val jsonBody = contentAsJson(result)
      jsonBody must not be null
    }

    "include rp field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "rp").get.toString mustEqual """{"id":"example.com","name":"Test App"}"""
    }

    "include user field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "user").get.toString mustEqual """{"id":"dXNlcjEyMw","name":"testuser","displayName":"Test User"}"""
    }

    "include challenge field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "challenge").as[String] mustEqual "dGVzdC1jaGFsbGVuZ2U"
    }

    "include pubKeyCredParams field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "pubKeyCredParams").get.toString mustEqual """[{"type":"public-key","alg":-7}]"""
    }

    "return 400 Bad Request when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.creationOptionsResult = Future.failed(new RuntimeException("Service error"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.creationOptionsResult = Future.failed(new RuntimeException("Service error"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.creationOptionsResult = Future.failed(new IllegalArgumentException("Invalid user"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/creation-options")
      val result = controller.creationOptions()(request)
      status(result) mustBe BAD_REQUEST
    }
  }

  "register" should {

    "return 204 No Content on success" in {
      val controller = createController()
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      status(result) mustBe NO_CONTENT
    }

    "return 400 Bad Request when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request when creation data is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockCreationData = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      status(result) mustBe BAD_REQUEST
    }

    "return error message when creation data is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockCreationData = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.registerResult = Future.failed(new RuntimeException("Registration failed"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.registerResult = Future.failed(new RuntimeException("Registration failed"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.registerResult = Future.failed(new IllegalArgumentException("Invalid registration data"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(POST, "/register")
      val result = controller.register()(request)
      status(result) mustBe BAD_REQUEST
    }
  }

  "authenticationOptions" should {

    "return 200 OK on success" in {
      val controller = createController()
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      status(result) mustBe OK
    }

    "return JSON content type on success" in {
      val controller = createController()
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      contentType(result) mustBe Some("application/json")
    }

    "return valid JSON response body" in {
      val controller = createController()
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      val jsonBody = contentAsJson(result)
      jsonBody must not be null
    }

    "include challenge field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "challenge").as[String] mustEqual "YXV0aC1jaGFsbGVuZ2U"
    }

    "include rpId field in JSON response" in {
      val controller = createController()
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      val jsonBody = contentAsJson(result)
      (jsonBody \ "rpId").as[String] mustEqual "example.com"
    }

    "return 400 Bad Request when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      status(result) mustBe BAD_REQUEST
    }

    "return error message when user ID is missing" in {
      val mockReqHelper = new MockRequestHelper()
      mockReqHelper.mockUserId = None
      val controller = createController(mockReqHelper)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 500 Internal Server Error when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.authenticationOptionsResult = Future.failed(new RuntimeException("Auth options failed"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      status(result) mustBe INTERNAL_SERVER_ERROR
    }

    "return error message when service fails" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.authenticationOptionsResult = Future.failed(new RuntimeException("Auth options failed"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      contentAsString(result) mustBe "Something went wrong"
    }

    "return 400 Bad Request for IllegalArgumentException from service" in {
      val mockService = new MockPasskeyVerificationService()
      mockService.authenticationOptionsResult = Future.failed(new IllegalArgumentException("Invalid auth request"))
      val controller = createController(mockService = mockService)
      val request = FakeRequest(GET, "/authentication-options")
      val result = controller.authenticationOptions()(request)
      status(result) mustBe BAD_REQUEST
    }
  }
}
