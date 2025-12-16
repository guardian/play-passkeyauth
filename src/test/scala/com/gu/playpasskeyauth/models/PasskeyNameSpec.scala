package com.gu.playpasskeyauth.models

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.EitherValues
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks

class PasskeyNameSpec extends AnyFlatSpec with Matchers with ScalaCheckPropertyChecks with EitherValues {

  import PasskeyNameSpec.*

  "PasskeyName.validate" should "reject null input" in {
    PasskeyName.validate(null).left.value shouldBe PasskeyName.ValidationError.Empty
  }

  it should "reject empty string" in {
    PasskeyName.validate("").left.value shouldBe PasskeyName.ValidationError.Empty
  }

  it should "reject whitespace-only string" in {
    PasskeyName.validate("   ").left.value shouldBe PasskeyName.ValidationError.Empty
  }

  it should "reject tab-only string" in {
    PasskeyName.validate("\t\t").left.value shouldBe PasskeyName.ValidationError.Empty
  }

  it should "accept name at maximum length" in {
    val maxLengthName = "a" * 255
    PasskeyName.validate(maxLengthName).value.value shouldBe maxLengthName
  }

  it should "reject name exceeding maximum length" in {
    val tooLongName = "a" * 256
    PasskeyName.validate(tooLongName).left.value shouldBe PasskeyName.ValidationError.TooLong(255)
  }

  it should "reject any name longer than 255 characters" in {
    forAll(Gen.chooseNum(256, 1000)) { length =>
      val longName = "a" * length
      PasskeyName.validate(longName).left.value shouldBe PasskeyName.ValidationError.TooLong(255)
    }
  }

  it should "accept alphanumeric names" in {
    forAll(genAlphanumericName) { name =>
      PasskeyName.validate(name).isRight shouldBe true
    }
  }

  it should "accept names with spaces" in {
    PasskeyName.validate("My Passkey").value.value shouldBe "My Passkey"
  }

  it should "accept names with hyphens" in {
    PasskeyName.validate("my-passkey").value.value shouldBe "my-passkey"
  }

  it should "accept names with underscores" in {
    PasskeyName.validate("my_passkey").value.value shouldBe "my_passkey"
  }

  it should "accept names with periods" in {
    PasskeyName.validate("my.passkey").value.value shouldBe "my.passkey"
  }

  it should "accept names with commas" in {
    PasskeyName.validate("passkey, main").value.value shouldBe "passkey, main"
  }

  it should "accept names with apostrophes" in {
    PasskeyName.validate("John's YubiKey").value.value shouldBe "John's YubiKey"
  }

  it should "accept names with parentheses" in {
    PasskeyName.validate("YubiKey (backup)").value.value shouldBe "YubiKey (backup)"
  }

  it should "accept unicode letters" in {
    PasskeyName.validate("日本語キー").value.value shouldBe "日本語キー"
  }

  it should "accept names with mixed allowed characters" in {
    forAll(genValidPasskeyName) { name =>
      PasskeyName.validate(name).isRight shouldBe true
    }
  }

  it should "reject names with angle brackets" in {
    PasskeyName.validate("my<script>key").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names with ampersand" in {
    PasskeyName.validate("key&value").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names with semicolon" in {
    PasskeyName.validate("key;drop table").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names with equals sign" in {
    PasskeyName.validate("key=value").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names with backtick" in {
    PasskeyName.validate("key`cmd`").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names with dollar sign" in {
    PasskeyName.validate("$HOME").left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
  }

  it should "reject names containing any dangerous character" in {
    forAll(genNameWithDangerousChar) { name =>
      PasskeyName.validate(name).left.value shouldBe PasskeyName.ValidationError.InvalidCharacters
    }
  }

  it should "trim leading whitespace" in {
    PasskeyName.validate("  MyKey").value.value shouldBe "MyKey"
  }

  it should "trim trailing whitespace" in {
    PasskeyName.validate("MyKey  ").value.value shouldBe "MyKey"
  }

  it should "trim both leading and trailing whitespace" in {
    PasskeyName.validate("  MyKey  ").value.value shouldBe "MyKey"
  }

  "PasskeyName.isValid" should "return true for valid names" in {
    forAll(genValidPasskeyName) { name =>
      PasskeyName.isValid(name) shouldBe true
    }
  }

  it should "return false for empty names" in {
    PasskeyName.isValid("") shouldBe false
  }

  it should "return false for names with invalid characters" in {
    forAll(genNameWithDangerousChar) { name =>
      PasskeyName.isValid(name) shouldBe false
    }
  }

  "ValidationError.Empty.message" should "describe the empty error" in {
    PasskeyName.ValidationError.Empty.message shouldBe "Passkey name cannot be empty"
  }

  "ValidationError.TooLong.message" should "include the max length" in {
    PasskeyName.ValidationError.TooLong(255).message shouldBe "Passkey name must not exceed 255 characters"
  }

  "ValidationError.InvalidCharacters.message" should "describe the invalid characters error" in {
    PasskeyName.ValidationError.InvalidCharacters.message shouldBe "Passkey name contains invalid characters"
  }
}

object PasskeyNameSpec {

  /** Generator for valid alphanumeric passkey names */
  val genAlphanumericName: Gen[String] =
    Gen.chooseNum(1, 50).flatMap(n => Gen.listOfN(n, Gen.alphaNumChar).map(_.mkString))

  /** Characters that are allowed in passkey names */
  val allowedSpecialChars: Seq[Char] = Seq(' ', '-', '_', '.', ',', '\'', '(', ')')

  /** Generator for valid passkey names with allowed special characters */
  val genValidPasskeyName: Gen[String] = for {
    length <- Gen.chooseNum(1, 100)
    chars <- Gen.listOfN(
      length,
      Gen.oneOf(
        Gen.alphaNumChar,
        Gen.oneOf(allowedSpecialChars)
      )
    )
    // Ensure we don't generate only whitespace
    if chars.exists(_ != ' ')
  } yield chars.mkString

  /** Dangerous characters that should be rejected */
  val dangerousChars: Seq[Char] = Seq('<', '>', '&', ';', '=', '`', '$', '"', '\\', '/', '!', '@', '#', '%', '^', '*',
    '+', '[', ']', '{', '}', '|', '~')

  /** Generator for names containing dangerous characters */
  val genNameWithDangerousChar: Gen[String] = for {
    prefix <- Gen.alphaStr.suchThat(_.nonEmpty)
    dangerousChar <- Gen.oneOf(dangerousChars)
    suffix <- Gen.alphaStr
  } yield s"$prefix$dangerousChar$suffix"
}
