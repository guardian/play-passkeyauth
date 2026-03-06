package com.gu.playpasskeyauth.models

import com.webauthn4j.data.attestation.authenticator.AAGUID
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.time.Instant

class PasskeySpec extends AnyFlatSpec with Matchers {

  import PasskeyTestFixtures.*

  "Passkey.recordAuthentication" should "update signCount" in {
    val passkey = samplePasskey(signCount = 1L)
    val updated = passkey.recordAuthentication(newCount = 5L, fixedClock)
    updated.signCount shouldBe 5L
  }

  it should "set lastUsedAt to the clock instant" in {
    val passkey = samplePasskey()
    val updated = passkey.recordAuthentication(newCount = 1L, fixedClock)
    updated.lastUsedAt shouldBe Some(fixedInstant)
  }

  it should "preserve all other fields" in {
    val passkey = samplePasskey()
    val updated = passkey.recordAuthentication(newCount = 2L, fixedClock)
    updated.id shouldBe passkey.id
    updated.name shouldBe passkey.name
    updated.credentialRecord shouldBe passkey.credentialRecord
    updated.createdAt shouldBe passkey.createdAt
    updated.aaguid shouldBe passkey.aaguid
  }

  "Passkey.fromRegistration" should "set createdAt from the clock" in {
    val passkey = Passkey.fromRegistration(sampleId, sampleName, stubCredentialRecord, fixedClock)
    passkey.createdAt shouldBe fixedInstant
  }

  it should "set lastUsedAt to None" in {
    val passkey = Passkey.fromRegistration(sampleId, sampleName, stubCredentialRecord, fixedClock)
    passkey.lastUsedAt shouldBe None
  }

  it should "set signCount to zero" in {
    val passkey = Passkey.fromRegistration(sampleId, sampleName, stubCredentialRecord, fixedClock)
    passkey.signCount shouldBe 0L
  }

  it should "use the provided id and name" in {
    val passkey = Passkey.fromRegistration(sampleId, sampleName, stubCredentialRecord, fixedClock)
    passkey.id shouldBe sampleId
    passkey.name shouldBe sampleName
  }

  it should "extract the aaguid from the credential record" in {
    val passkey = Passkey.fromRegistration(sampleId, sampleName, stubCredentialRecord, fixedClock)
    passkey.aaguid shouldBe AAGUID.ZERO
  }
}
