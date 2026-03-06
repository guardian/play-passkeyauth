package com.gu.playpasskeyauth.models

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import play.api.libs.json.{JsError, JsString, JsSuccess, Json}

import java.time.Instant

class JsonEncodingsSpec extends AnyFlatSpec with Matchers {

  import JsonEncodings.given
  import PasskeyTestFixtures.*

  "Writes[Passkey]" should "serialise id as base64url string" in {
    val json = Json.toJson(samplePasskey())
    (json \ "id").as[String] shouldBe sampleId.toBase64Url
  }

  it should "serialise name as string value" in {
    val json = Json.toJson(samplePasskey())
    (json \ "name").as[String] shouldBe sampleName.value
  }

  it should "serialise createdAt as epoch millis" in {
    val passkey = samplePasskey()
    val json = Json.toJson(passkey)
    (json \ "createdAt").as[Long] shouldBe passkey.createdAt.toEpochMilli
  }

  it should "serialise lastUsedAt as null when None" in {
    val json = Json.toJson(samplePasskey(lastUsedAt = None))
    (json \ "lastUsedAt").asOpt[Long] shouldBe None
  }

  it should "serialise lastUsedAt as epoch millis when present" in {
    val usedAt = Instant.parse("2024-06-01T12:00:00Z")
    val json = Json.toJson(samplePasskey(lastUsedAt = Some(usedAt)))
    (json \ "lastUsedAt").as[Long] shouldBe usedAt.toEpochMilli
  }

  "Writes[PasskeyId]" should "serialise as base64url string" in {
    val json = Json.toJson(sampleId)
    json.as[String] shouldBe sampleId.toBase64Url
  }

  "Writes[PasskeyName]" should "serialise as string value" in {
    val json = Json.toJson(sampleName)
    json.as[String] shouldBe sampleName.value
  }

  "Reads[PasskeyId]" should "deserialise from base64url string" in {
    val json = JsString(sampleId.toBase64Url)
    json.validate[PasskeyId] shouldBe JsSuccess(sampleId)
  }

  it should "round-trip through Writes and Reads" in {
    val written = Json.toJson(sampleId)
    written.validate[PasskeyId] shouldBe JsSuccess(sampleId)
  }

  "Reads[PasskeyName]" should "deserialise from valid string" in {
    val json = JsString("My YubiKey")
    json.validate[PasskeyName] shouldBe JsSuccess(PasskeyName("My YubiKey"))
  }

  it should "reject empty string" in {
    val json = JsString("")
    json.validate[PasskeyName] shouldBe a[JsError]
  }

  it should "reject string with invalid characters" in {
    val json = JsString("<script>alert(1)</script>")
    json.validate[PasskeyName] shouldBe a[JsError]
  }

  it should "round-trip through Writes and Reads" in {
    val written = Json.toJson(sampleName)
    written.validate[PasskeyName] shouldBe JsSuccess(sampleName)
  }

  "Reads[UserId]" should "deserialise from valid string" in {
    val json = JsString("user-123")
    json.validate[UserId] shouldBe JsSuccess(UserId("user-123"))
  }
}
