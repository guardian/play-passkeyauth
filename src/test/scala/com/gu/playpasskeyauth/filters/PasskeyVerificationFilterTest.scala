package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestExtractor
import com.webauthn4j.data.AuthenticationData
import org.mockito.ArgumentMatchers.{any, eq as eqTo}
import org.mockito.Mockito.*
import org.scalatest.concurrent.ScalaFutures
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.libs.json.JsObject
import play.api.mvc.Results.{BadRequest, InternalServerError}
import play.api.mvc.{Request, Result}
import play.api.test.FakeRequest

import scala.concurrent.{ExecutionContext, Future}

class PasskeyVerificationFilterTest extends PlaySpec with MockitoSugar with ScalaFutures {

  given ExecutionContext = ExecutionContext.global

  private val testUserId = "test-user-123"

  private def createFilter(
      verifier: PasskeyVerificationService = mock[PasskeyVerificationService],
      RequestExtractor: RequestExtractor[Request] = mock[RequestExtractor[Request]]
  ): PasskeyVerificationFilter[Request] = {
    given RequestExtractor[Request] = RequestExtractor
    new PasskeyVerificationFilter[Request](verifier)
  }

  "filter" must {
    "return None when verification succeeds" in {
      val reqExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()
      val authData = mock[JsObject]
      val verifiedAuthData = mock[AuthenticationData]
      val verifier = mock[PasskeyVerificationService]

      when(reqExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(reqExtractor.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(verifiedAuthData))

      val filter = createFilter(verifier, reqExtractor)
      val result = filter.filter(request).futureValue

      result mustBe None
    }

    "return BadRequest when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(None)

      val filter = createFilter(RequestExtractor = RequestExtractor)
      val result = filter.filter(request).futureValue

      result mustBe Some(BadRequest("Something went wrong"))
    }

    "return BadRequest when authentication data is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(RequestExtractor = RequestExtractor)
      val result = filter.filter(request).futureValue

      result mustBe Some(BadRequest("Something went wrong"))
    }

    "return InternalServerError when verification fails" in {
      val verifier = mock[PasskeyVerificationService]
      val RequestExtractor = mock[RequestExtractor[Request]]
      val authData = mock[JsObject]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.failed(new RuntimeException("Verification failed")))

      val filter = createFilter(verifier, RequestExtractor)
      val result = filter.filter(request).futureValue

      result mustBe Some(InternalServerError("Something went wrong"))
    }

    "call verifier with correct user ID" in {
      val verifier = mock[PasskeyVerificationService]
      val RequestExtractor = mock[RequestExtractor[Request]]
      val authData = mock[JsObject]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(authData))

      val filter = createFilter(verifier, RequestExtractor)
      filter.filter(request).futureValue

      verify(verifier).verify(eqTo(testUserId), any[JsObject])
    }

    "call verifier with correct authentication data" in {
      val verifier = mock[PasskeyVerificationService]
      val RequestExtractor = mock[RequestExtractor[Request]]
      val authData = mock[JsObject]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(authData))

      val filter = createFilter(verifier, RequestExtractor)
      filter.filter(request).futureValue

      verify(verifier).verify(any[String], eqTo(authData))
    }

    "call RequestExtractor.findUserId with correct request" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(None)

      val filter = createFilter(RequestExtractor = RequestExtractor)
      filter.filter(request).futureValue

      verify(RequestExtractor).findUserId(eqTo(request))
    }

    "call RequestExtractor.findAuthenticationData with correct request when user ID exists" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(RequestExtractor = RequestExtractor)
      filter.filter(request).futureValue

      verify(RequestExtractor).findAuthenticationData(eqTo(request))
    }

    "not call RequestExtractor.findAuthenticationData when user ID is missing" in {
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(None)

      val filter = createFilter(RequestExtractor = RequestExtractor)
      filter.filter(request).futureValue

      verify(RequestExtractor, never()).findAuthenticationData(any())
    }

    "not call verifier when user ID is missing" in {
      val verifier = mock[PasskeyVerificationService]
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(None)

      val filter = createFilter(verifier, RequestExtractor)
      filter.filter(request).futureValue

      verify(verifier, never()).verify(any[String], any[JsObject])
    }

    "not call verifier when authentication data is missing" in {
      val verifier = mock[PasskeyVerificationService]
      val RequestExtractor = mock[RequestExtractor[Request]]
      val request = FakeRequest()

      when(RequestExtractor.findUserId(request)).thenReturn(Some(testUserId))
      when(RequestExtractor.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(verifier, RequestExtractor)
      filter.filter(request).futureValue

      verify(verifier, never()).verify(any[String], any[JsObject])
    }
  }
}
