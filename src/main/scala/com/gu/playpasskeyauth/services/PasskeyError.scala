package com.gu.playpasskeyauth.services

import com.gu.playpasskeyauth.models.PasskeyName.ValidationError

/** Domain errors for passkey operations.
  *
  * These represent expected failure cases that can occur during passkey registration and authentication. They are
  * distinct from unexpected runtime errors (like database failures) and should be handled explicitly by client code.
  */
enum PasskeyError {

  /** The passkey name failed validation. */
  case InvalidName(error: ValidationError)

  /** A passkey with the given name already exists for this user. */
  case DuplicateName(name: String)

  /** The requested passkey was not found or doesn't belong to the user. */
  case PasskeyNotFound

  /** The challenge has expired. The user should restart the registration or authentication flow. */
  case ChallengeExpired

  /** The user-facing error message. */
  def message: String = this match {
    case InvalidName(error)  => error.message
    case DuplicateName(name) => s"A passkey with the name '$name' already exists."
    case PasskeyNotFound     => "Passkey not found."
    case ChallengeExpired    => "The challenge has expired. Please try again."
  }
}

final case class PasskeyException(error: PasskeyError) extends Exception(error.message)
