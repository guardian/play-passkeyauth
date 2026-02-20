package com.gu.playpasskeyauth.models

import play.api.libs.json.{JsString, Writes}

/** Validated and sanitised passkey name.
  *
  * Passkey names are user-provided identifiers that help users recognise their credentials. They are displayed in
  * browser dialogues and stored in the relying party's database, so validation is important for both security and UX.
  *
  * This case class can only be constructed through [[PasskeyName.validate]] (which validates) or [[PasskeyName.apply]]
  * (which throws on invalid input), ensuring all passkey names in the system have been validated and sanitised.
  *
  * @param value
  *   The validated and trimmed passkey name string
  * @example
  *   {{{
  * PasskeyName.validate("My YubiKey") match
  *   case Right(name) => println(s"Valid name: ${name.value}")
  *   case Left(error) => println(s"Invalid: ${error.message}")
  *   }}}
  */
case class PasskeyName private (value: String) {
  require(value.trim.nonEmpty, "Passkey name must not be empty")
  require(value.length <= PasskeyName.MaxLength, s"Passkey name must not exceed ${PasskeyName.MaxLength} characters")
  require(PasskeyName.AllowedPattern.matches(value), "Passkey name contains invalid characters")
}

object PasskeyName {

  /** Maximum allowed length for passkey names */
  private val MaxLength: Int = 255

  /** Minimum allowed length for passkey names */
  private val MinLength: Int = 1

  /** Pattern for allowed characters: alphanumeric, spaces, hyphens, underscores, periods, and common punctuation */
  private val AllowedPattern = "^[\\p{L}\\p{N}\\s\\-_.,'()]+$".r

  /** Validation errors for passkey names */
  enum ValidationError {
    case Empty
    case TooLong(maxLength: Int)
    case InvalidCharacters

    def message: String = this match {
      case Empty              => "Passkey name cannot be empty"
      case TooLong(maxLength) => s"Passkey name must not exceed $maxLength characters"
      case InvalidCharacters  => "Passkey name contains invalid characters"
    }
  }

  /** Creates a PasskeyName from a string, throwing an exception if validation fails.
    *
    * @param name
    *   The raw passkey name from user input
    * @return
    *   The validated PasskeyName
    * @throws IllegalArgumentException
    *   if validation fails
    */
  def apply(name: String): PasskeyName = {
    validate(name) match {
      case Right(passkeyName) => passkeyName
      case Left(error)        => throw new IllegalArgumentException(error.message)
    }
  }

  /** Validates a passkey name.
    *
    * @param name
    *   The raw passkey name from user input
    * @return
    *   Either a validation error or the validated PasskeyName
    */
  def validate(name: String): Either[ValidationError, PasskeyName] = {
    val trimmed = Option(name).map(_.trim).getOrElse("")
    if trimmed.isEmpty then Left(ValidationError.Empty)
    else if trimmed.length > MaxLength then Left(ValidationError.TooLong(MaxLength))
    else if !AllowedPattern.matches(trimmed) then Left(ValidationError.InvalidCharacters)
    else Right(new PasskeyName(trimmed))
  }

  /** Checks if a passkey name is valid without returning the sanitised value.
    *
    * @param name
    *   The passkey name to check
    * @return
    *   true if valid, false otherwise
    */
  def isValid(name: String): Boolean = validate(name).isRight

  given Writes[PasskeyName] = Writes { name => JsString(name.value) }
}
