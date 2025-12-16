package com.gu.playpasskeyauth.models

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class UserIdSpec extends AnyFlatSpec with Matchers {

  "UserId.apply" should "create UserId from valid string" in {
    val userId = UserId("user@example.com")
    userId.value shouldBe "user@example.com"
  }

  it should "reject empty string" in {
    an[IllegalArgumentException] should be thrownBy UserId("")
  }

  it should "reject whitespace-only string" in {
    an[IllegalArgumentException] should be thrownBy UserId("   ")
  }

  it should "reject tab-only string" in {
    an[IllegalArgumentException] should be thrownBy UserId("\t\t")
  }

  it should "reject string with leading/trailing whitespace" in {
    an[IllegalArgumentException] should be thrownBy UserId("  user@example.com  ")
  }

  "UserId.value" should "return the underlying string" in {
    val userId = UserId("test-user-123")
    userId.value shouldBe "test-user-123"
  }

  "UserId.bytes" should "return UTF-8 encoded bytes" in {
    val userId = UserId("test")
    userId.bytes shouldBe "test".getBytes("UTF-8")
  }

  it should "handle unicode characters" in {
    val userId = UserId("用户")
    userId.bytes shouldBe "用户".getBytes("UTF-8")
  }
}
