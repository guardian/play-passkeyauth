package com.gu.playpasskeyauth.models

import play.api.libs.json.{Json, Writes}

import java.time.Instant

/** Information stored about a registered passkey.
  *
  * @param id
  *   The unique identifier for this passkey (credential ID)
  * @param name
  *   The user-provided friendly name for this passkey
  * @param createdAt
  *   When the passkey was registered
  * @param lastUsedAt
  *   When the passkey was last used for authentication, if ever
  */
case class PasskeyInfo(
    id: PasskeyId,
    name: PasskeyName,
    createdAt: Instant,
    lastUsedAt: Option[Instant]
)

object PasskeyInfo {
  given Writes[PasskeyInfo] = Json.writes[PasskeyInfo]
}
