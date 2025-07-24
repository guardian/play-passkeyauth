package com.gu.playpasskeyauth.model

import com.webauthn4j.data.attestation.authenticator.AAGUID

import java.time.Instant

case class PasskeyMetadata(
    id: String,
    name: String,
    registrationTime: Instant,
    // Identifies the model of the authenticator device that created the passkey
    aaguid: AAGUID,
    lastUsedTime: Option[Instant],
    authenticator: Option[PasskeyAuthenticator]
)
