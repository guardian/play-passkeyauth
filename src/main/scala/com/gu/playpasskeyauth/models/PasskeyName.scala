package com.gu.playpasskeyauth.models

/** Validates and sanitizes passkey names provided by users.
  *
  * Passkey names are user-provided identifiers that help users recognize their credentials. They are displayed in
  * browser dialogs and stored in the relying party's database, so validation is important for both security and UX.
  */
object PasskeyName:

  /** Maximum allowed length for passkey names */
  val MaxLength: Int = 255

  /** Minimum allowed length for passkey names */
  val MinLength: Int = 1

  /** Pattern for allowed characters: alphanumeric, spaces, hyphens, underscores, periods, and common punctuation */
  private val AllowedPattern = "^[\\p{L}\\p{N}\\s\\-_\\.,'()]+$".r

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
    *   Either a validation error or the sanitized (trimmed) name
    */
  def validate(name: String): Either[ValidationError, String] =
    val trimmed = Option(name).map(_.trim).getOrElse("")
    if trimmed.isEmpty then Left(ValidationError.Empty)
    else if trimmed.length > MaxLength then Left(ValidationError.TooLong(MaxLength))
    else if !AllowedPattern.matches(trimmed) then Left(ValidationError.InvalidCharacters)
    else Right(trimmed)

  /** Checks if a passkey name is valid without returning the sanitized value.
    *
    * @param name
    *   The passkey name to check
    * @return
    *   true if valid, false otherwise
    */
  def isValid(name: String): Boolean = validate(name).isRight
