package com.gu.playpasskeyauth.services

/** Distinguishes between registration and authentication challenges.
  *
  * Used by [[PasskeyChallengeRepository]] to determine which type of challenge to store or retrieve. This avoids
  * duplicating load/insert/delete methods for each challenge type.
  */
enum ChallengeType {
  case Registration
  case Authentication
}
