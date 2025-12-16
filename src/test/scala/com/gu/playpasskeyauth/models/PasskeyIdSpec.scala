package com.gu.playpasskeyauth.models

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class PasskeyIdSpec extends AnyFlatSpec with Matchers {

  "PasskeyId.apply" should "create PasskeyId from valid byte array" in {
    val bytes = Array[Byte](1, 2, 3, 4, 5)
    val passkeyId = PasskeyId(bytes)
    passkeyId.bytes shouldBe bytes
  }

  it should "reject empty array" in {
    an[IllegalArgumentException] should be thrownBy PasskeyId(Array.empty[Byte])
  }

  "PasskeyId.fromBase64Url" should "decode valid base64url string" in {
    // "test" in base64url is "dGVzdA"
    val passkeyId = PasskeyId.fromBase64Url("dGVzdA")
    passkeyId.bytes shouldBe "test".getBytes("UTF-8")
  }

  it should "reject empty string" in {
    an[IllegalArgumentException] should be thrownBy PasskeyId.fromBase64Url("")
  }

  "PasskeyId.toBase64Url" should "encode to base64url string" in {
    val passkeyId = PasskeyId("test".getBytes("UTF-8"))
    passkeyId.toBase64Url shouldBe "dGVzdA"
  }

  it should "round-trip correctly" in {
    val original = "some-credential-id-bytes"
    val passkeyId = PasskeyId(original.getBytes("UTF-8"))
    val encoded = passkeyId.toBase64Url
    val decoded = PasskeyId.fromBase64Url(encoded)
    decoded.bytes shouldBe original.getBytes("UTF-8")
  }

  "PasskeyId.bytes" should "return the underlying byte array" in {
    val bytes = Array[Byte](10, 20, 30, 40, 50)
    val passkeyId = PasskeyId(bytes)
    passkeyId.bytes shouldBe bytes
  }
}
