package com.gu.playpasskeyauth.models

/** Validated and sanitised passkey name.
  *
  * Passkey names are user-provided identifiers that help users recognise their credentials. They are displayed in
  * browser dialogues and stored in the relying party's database, so validation is important for both security and UX.
  *
  * This is an opaque type that can only be constructed through [[PasskeyName.validate]], ensuring all passkey names in
  * the system have been validated and sanitised.
  *
  * @example
  *   {{{
  * PasskeyName.validate("My YubiKey") match
  *   case Right(name) => println(s"Valid name: ${name.value}")
  *   case Left(error) => println(s"Invalid: ${error.message}")
  *   }}}
  */
opaque type PasskeyName = String

object PasskeyName:

  /** Maximum allowed length for passkey names */
  private val MaxLength: Int = 255

  /** Minimum allowed length for passkey names */
  private val MinLength: Int = 1

  /** Pattern for allowed characters: alphanumeric, spaces, hyphens, underscores, periods, and common punctuation */
  private val AllowedPattern = "^[\\p{L}\\p{N}\\s\\-_.,'()]+$".r

  /** Validation errors for passkey names */
  enum ValidationError:
    case Empty
    case TooLong(maxLength: Int)
    case InvalidCharacters

    def message: String = this match
      case Empty              => "Passkey name cannot be empty"
      case TooLong(maxLength) => s"Passkey name must not exceed $maxLength characters"
      case InvalidCharacters  => "Passkey name contains invalid characters"

  /** Validates a passkey name.
    *
    * @param name
    *   The raw passkey name from user input
    * @return
    *   Either a validation error or the validated PasskeyName
    */
  def validate(name: String): Either[ValidationError, PasskeyName] =
    val trimmed = Option(name).map(_.trim).getOrElse("")
    if trimmed.isEmpty then Left(ValidationError.Empty)
    else if trimmed.length > MaxLength then Left(ValidationError.TooLong(MaxLength))
    else if !AllowedPattern.matches(trimmed) then Left(ValidationError.InvalidCharacters)
    else Right(trimmed)

  /** Checks if a passkey name is valid without returning the sanitised value.
    *
    * @param name
    *   The passkey name to check
    * @return
    *   true if valid, false otherwise
    */
  def isValid(name: String): Boolean = validate(name).isRight

  /** Extension methods for PasskeyName */
  extension (name: PasskeyName)
    /** Returns the underlying string value */
    def value: String = name
