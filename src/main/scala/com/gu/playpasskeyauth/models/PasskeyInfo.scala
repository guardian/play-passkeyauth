package com.gu.playpasskeyauth.models

import com.webauthn4j.data.attestation.authenticator.AAGUID
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
// TODO: we probably don't need this - can do everything with Passkey class
case class PasskeyInfo(
    id: PasskeyId,
    name: PasskeyName,
    aaguid: AAGUID,
    createdAt: Instant,
    lastUsedAt: Option[Instant]
)
