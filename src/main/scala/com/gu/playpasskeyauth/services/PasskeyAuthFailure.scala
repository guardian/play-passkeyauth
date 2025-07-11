package com.gu.playpasskeyauth.services

enum PasskeyAuthFailure(val message: String):
  case RepositoryFailure(override val message: String) extends PasskeyAuthFailure(message)
  case VerificationFailure(override val message: String) extends PasskeyAuthFailure(message)
  case NotFoundFailure(override val message: String) extends PasskeyAuthFailure(message)
