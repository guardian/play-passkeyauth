# Play Passkey Authentication

[![Build Status](https://github.com/guardian/play-passkeyauth/workflows/CI/badge.svg)](https://github.com/guardian/play-passkeyauth/actions)
[![Latest Release](https://img.shields.io/maven-central/v/com.webauthn4j/webauthn4j-core.svg)](https://search.maven.org/artifact/com.webauthn4j/webauthn4j-core)
[![Scala Version](https://img.shields.io/badge/scala-3.3-red.svg)](https://scala-lang.org/)
[![Play Version](https://img.shields.io/badge/play-3.0-green.svg)](https://www.playframework.com/)

A library that integrates [webauthn4j](https://github.com/webauthn4j/webauthn4j) in a 
[Play framework](https://www.playframework.com/) app,   
providing the server-side registration and verification services of 
the [Web Authentication standard](https://www.passkeys.com/what-is-webauthn).

## Why use this library?

TODO explains benefits over manual webauthn4j integration

## Installation
Add to your `build.sbt`:
```scala
libraryDependencies += "com.yourorg" %% "play-passkey-auth" % "0.0.1"
```

## API

TODO

TODO: add seq diag

## Configuration

TODO

## Structure

The library is storage-agnostic.  You must decide how best to store passkey data in your infrastructure.
Consequently, the integration depends on the implementation of some service traits.

## Integration steps

1. Implement [PasskeyRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyRepository.scala).
1. Implement [PasskeyChallengeRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyChallengeRepository.scala).
1. Create an instance of [web.RequestExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestExtractor.scala) for your user handle type.
1. Implement [BasePasskeyController](src/main/scala/com/gu/playpasskeyauth/controllers/BasePasskeyController.scala).

## Code Examples
 show actual Scala/Play code
 how to handle common failure cases
 how it fits into existing Play apps

TODO: Below to be moved elsewhere
## General information about passkeys

### Terminology

#### Relying Party (RP)

The web application or service that relies on passkey authentication to verify user identity.

Key characteristics:

* The backend application that handles authentication
* Trusts the authenticator's cryptographic proof of user identity
* Stores public keys and credential mappings for registered users
* Creates cryptographic challenges during registration and authentication
* Validates signatures and attestation data from authenticators

Responsibilities:

* Generates and verifies cryptographic challenges
* Stores public keys securely after registration
* Validates assertion signatures during authentication
* Implements security policies (which authenticators accept)
* Manages user sessions after successful authentication
* Handles credential lifecycle (registration, authentication, deletion)

In the passkey flow:

The RP initiates both registration and authentication ceremonies by sending challenges to the client (browser), 
then verifies the cryptographic responses to establish trust in the user's identity.

#### Authenticator

The hardware or software component that generates, stores and uses passkeys for authentication.

Types:

* **Platform** authenticators are built into devices (Touch ID, Face ID, Windows Hello, Android biometrics).
* **Cross-platform** authenticators are external devices (USB security keys, Bluetooth authenticators).
* **Hybrid** authenticators are smartphones that can authenticate for other devices via QR codes, Bluetooth, NFC, etc.

Responsibilities:

* Generates cryptographic key pairs during passkey creation
* Stores private keys securely (in Secure Enclave, TPM, or secure hardware)
* Performs user verification (biometrics, PIN, device unlock)
* Creates attestation data during registration
* Signs authentication challenges using stored private keys
* Manages credential lifecycle on the device
* Protects against unauthorised access to stored credentials

Security features:

* Private keys never leave the authenticator
* User presence and verification required for operations
* Resistant to phishing attacks (domain binding)
* Counter mechanisms to prevent replay attacks

In the passkey flow:

The authenticator is the trusted component that proves user identity through cryptographic signatures, 
enabling passwordless authentication while keeping credentials secure on the user's device.

#### Attestation data

Cryptographic proof that a passkey was created by a legitimate [authenticator](#authenticator) during the 
registration process.

Attestation data includes:
* Authenticator data: Information about the [authenticator](#authenticator) (AAGUID, flags, counter, credential data)
* Attestation statement: Cryptographic signature proving the [authenticator](#authenticator)'s authenticity
* Public key: The newly generated public key for the credential
* Credential ID: Unique identifier for this specific passkey
* Client Data Hash: Hash of the challenge and other client-side data

Purpose:

* Proves to the [RP](#relying-party-rp) that the passkey was created by a trusted [authenticator](#authenticator).
* Prevents malicious software from creating fake credentials
* Allows [RP](#relying-party-rp)s to verify the [authenticator](#authenticator) model and security characteristics
* Provides assurance about the security level of the credential

Types:

* Self attestation: [Authenticator](#authenticator) signs with its own key (basic trust)
* Basic attestation: Uses manufacturer certificate to prove authenticity
* AttCA attestation: Uses certificate chain from trusted certificate authority
* None: No attestation provided (anonymous)

The [RP](#relying-party-rp) can use this data to make policy decisions about whether to accept the credential based on 
the [authenticator](#authenticator)'s security properties.

#### Assertion data

Cryptographic proof that a user successfully authenticated with their passkey during the authentication process.

Assertion data includes:
* Authenticator data: Information about the authentication event (RP ID hash, flags, counter)
* Signature: Digital signature created using the user's private key
* User handle: Optional user identifier from the credential
* Client data Json: Contains the challenge, origin, and other client-side information

Purpose:

* Proves to the [RP](#relying-party-rp) that the user possesses the private key corresponding to 
the registered public key
* Demonstrates that user verification occurred on the [authenticator](#authenticator)
* Provides protection against replay attacks through signature verification
* Confirms the authentication occurred for the correct [RP](#relying-party-rp) and challenge

The [RP](#relying-party-rp) verifies assertion data using the stored public key to confirm the user's identity and 
complete the authentication process.

---

### Events in the lifecycle of a passkey

#### Creation (in [Authenticator](#authenticator))
1. User initiates passkey creation in browser
1. [RP](#relying-party-rp) sends challenge and user information to browser
1. Browser forwards request to [authenticator](#authenticator)
1. [Authenticator](#authenticator) generates a new cryptographic key pair
1. Private key is stored securely in the [authenticator](#authenticator)
1. User verification occurs (biometric, PIN, or device unlock)
1. [Authenticator](#authenticator) creates [attestation data](#attestation-data), signs it and returns it to browser

#### Registration (in [RP](#relying-party-rp))
1. Browser sends response containing signed [attestation data](#attestation-data) to [RP](#relying-party-rp)
1. [RP](#relying-party-rp) verifies attestation and challenge signature
1. [RP](#relying-party-rp) stores public key, credential ID and user ID
1. Registration complete - passkey is now associated with user account

#### Authentication (in [Authenticator](#authenticator))
1. User initiates authentication process in browser
1. [RP](#relying-party-rp) sends authentication challenge with allowed credential IDs
1. [Authenticator](#authenticator) prompts for user verification
1. User provides biometric/PIN verification
1. [Authenticator](#authenticator) signs challenge with stored private key
1. [Authenticator](#authenticator) returns response containing [assertion data](#assertion-data) to browser

#### Verification (in [RP](#relying-party-rp))
1. Browser sends response containing [assertion data](#assertion-data) to [RP](#relying-party-rp)
1. [RP](#relying-party-rp) verifies the signature using stored public key
1. [RP](#relying-party-rp) validates challenge, origin, and other security parameters
1. [RP](#relying-party-rp) checks counter values to prevent replay attacks
1. If verification succeeds, user is authenticated
1. [RP](#relying-party-rp) establishes authenticated session

#### Deletion from [RP](#relying-party-rp)
> [!WARNING]  
> This library's functionality doesn't cover passkey deletion.
1. User requests passkey removal from account
1. [RP](#relying-party-rp) removes stored public key and credential mapping
1. The passkey will remain on the [authenticator](#authenticator) unless the user has some means of removing it

---

### References

* https://webauthn4j.github.io/webauthn4j/en/
* https://webauthn.guide/
* https://www.webauthn.me/
* https://www.passkeys.com/what-is-webauthn
* https://webauthn.io/
* https://passkeys.dev/
* https://developers.google.com/identity/passkeys/developer-guides
* https://debugger.simplewebauthn.dev/
* https://www.webauthn.me/browser-support
* https://fidoalliance.org/metadata/
