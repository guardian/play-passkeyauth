package com.gu.playpasskeyauth.filters

import com.gu.playpasskeyauth.services.PasskeyVerificationService
import com.gu.playpasskeyauth.web.RequestHelper
import com.webauthn4j.data.AuthenticationData
import org.mockito.ArgumentMatchers.{any, eq as eqTo}
import org.mockito.Mockito.*
import org.scalatest.concurrent.ScalaFutures
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.mvc.Results.{BadRequest, InternalServerError}
import play.api.mvc.{Request, Result}
import play.api.test.FakeRequest

import scala.concurrent.{ExecutionContext, Future}

class PasskeyVerificationFilterTest extends PlaySpec with MockitoSugar with ScalaFutures {

  given ExecutionContext = ExecutionContext.global

  private val testUserId = "test-user-123"

  private def createFilter(
      verifier: PasskeyVerificationService = mock[PasskeyVerificationService],
      requestHelper: RequestHelper[Request] = mock[RequestHelper[Request]]
  ): PasskeyVerificationFilter[Request] = {
    given RequestHelper[Request] = requestHelper
    new PasskeyVerificationFilter[Request](verifier)
  }

  "filter" must {
    "return None when verification succeeds" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val authData = mock[AuthenticationData]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(authData))

      val filter = createFilter(verifier, requestHelper)
      val result = filter.filter(request).futureValue

      result mustBe None
    }

    "return BadRequest when user ID is missing" in {
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(None)

      val filter = createFilter(requestHelper = requestHelper)
      val result = filter.filter(request).futureValue

      result mustBe Some(BadRequest("Something went wrong"))
    }

    "return BadRequest when authentication data is missing" in {
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(requestHelper = requestHelper)
      val result = filter.filter(request).futureValue

      result mustBe Some(BadRequest("Something went wrong"))
    }

    "return InternalServerError when verification fails" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val authData = mock[AuthenticationData]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.failed(new RuntimeException("Verification failed")))

      val filter = createFilter(verifier, requestHelper)
      val result = filter.filter(request).futureValue

      result mustBe Some(InternalServerError("Something went wrong"))
    }

    "call verifier with correct user ID" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val authData = mock[AuthenticationData]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(authData))

      val filter = createFilter(verifier, requestHelper)
      filter.filter(request).futureValue

      verify(verifier).verify(eqTo(testUserId), any[AuthenticationData])
    }

    "call verifier with correct authentication data" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val authData = mock[AuthenticationData]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(Some(authData))
      when(verifier.verify(testUserId, authData)).thenReturn(Future.successful(authData))

      val filter = createFilter(verifier, requestHelper)
      filter.filter(request).futureValue

      verify(verifier).verify(any[String], eqTo(authData))
    }

    "call requestHelper.findUserId with correct request" in {
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(None)

      val filter = createFilter(requestHelper = requestHelper)
      filter.filter(request).futureValue

      verify(requestHelper).findUserId(eqTo(request))
    }

    "call requestHelper.findAuthenticationData with correct request when user ID exists" in {
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(requestHelper = requestHelper)
      filter.filter(request).futureValue

      verify(requestHelper).findAuthenticationData(eqTo(request))
    }

    "not call requestHelper.findAuthenticationData when user ID is missing" in {
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(None)

      val filter = createFilter(requestHelper = requestHelper)
      filter.filter(request).futureValue

      verify(requestHelper, never()).findAuthenticationData(any())
    }

    "not call verifier when user ID is missing" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(None)

      val filter = createFilter(verifier, requestHelper)
      filter.filter(request).futureValue

      verify(verifier, never()).verify(any[String], any[AuthenticationData])
    }

    "not call verifier when authentication data is missing" in {
      val verifier = mock[PasskeyVerificationService]
      val requestHelper = mock[RequestHelper[Request]]
      val request = FakeRequest()

      when(requestHelper.findUserId(request)).thenReturn(Some(testUserId))
      when(requestHelper.findAuthenticationData(request)).thenReturn(None)

      val filter = createFilter(verifier, requestHelper)
      filter.filter(request).futureValue

      verify(verifier, never()).verify(any[String], any[AuthenticationData])
    }
  }
}
