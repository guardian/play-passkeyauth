package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.PasskeyName.ValidationError
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class PasskeyErrorSpec extends AnyFlatSpec with Matchers {

  "PasskeyError.InvalidName" should "provide a message from the validation error" in {
    val error = PasskeyError.InvalidName(ValidationError.Empty)
    error.message shouldBe "Passkey name cannot be empty"
  }

  it should "provide a message for TooLong error" in {
    val error = PasskeyError.InvalidName(ValidationError.TooLong(255))
    error.message shouldBe "Passkey name must not exceed 255 characters"
  }

  it should "provide a message for InvalidCharacters error" in {
    val error = PasskeyError.InvalidName(ValidationError.InvalidCharacters)
    error.message shouldBe "Passkey name contains invalid characters"
  }

  "PasskeyError.DuplicateName" should "include the duplicate name in the message" in {
    val error = PasskeyError.DuplicateName("My YubiKey")
    error.message shouldBe "A passkey with the name 'My YubiKey' already exists."
  }

  "PasskeyError.PasskeyNotFound" should "provide a not found message" in {
    val error = PasskeyError.PasskeyNotFound
    error.message shouldBe "Passkey not found."
  }

  "PasskeyError.ChallengeExpired" should "provide an expiration message" in {
    val error = PasskeyError.ChallengeExpired
    error.message shouldBe "The challenge has expired. Please try again."
  }

  "PasskeyException" should "wrap PasskeyError with its message" in {
    val error = PasskeyError.DuplicateName("Test Key")
    val exception = PasskeyException(error)
    exception.getMessage shouldBe "A passkey with the name 'Test Key' already exists."
    exception.error shouldBe error
  }

  it should "wrap PasskeyNotFound error" in {
    val exception = PasskeyException(PasskeyError.PasskeyNotFound)
    exception.getMessage shouldBe "Passkey not found."
  }
}
