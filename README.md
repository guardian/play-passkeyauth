# Play Passkey Authentication

[![Build Status](https://github.com/guardian/play-passkeyauth/workflows/CI/badge.svg)](https://github.com/guardian/play-passkeyauth/actions)

[//]: # (TODO)
[//]: # ([![Latest Release]&#40;https://img.shields.io/maven-central/v/com.webauthn4j/webauthn4j-core.svg&#41;]&#40;https://search.maven.org/artifact/com.webauthn4j/webauthn4j-core&#41;)
[![Scala Version](https://img.shields.io/badge/scala-3.3-red.svg)](https://scala-lang.org/)
[![Play Version](https://img.shields.io/badge/play-3.0-green.svg)](https://www.playframework.com/)

A library that integrates [webauthn4j](https://github.com/webauthn4j/webauthn4j) in a 
[Play framework](https://www.playframework.com/) app,   
providing the server-side registration and verification services of 
the [Web Authentication standard](https://www.passkeys.com/what-is-webauthn).

## Why use this library?

The benefits of using this library over integrating webauthn4j directly include:

### Simplified Integration
Pre-built Play Framework components provide ready-to-use controllers and action builders that integrate directly with 
Play's routing and request handling, eliminating boilerplate.
Storage abstraction defines clear interfaces (PasskeyRepository, PasskeyChallengeRepository) so you only implement 
storage logic without worrying about WebAuthn protocol details.

### Reduced Complexity
WebAuthn protocol handling manages the complex challenge-response flow, credential creation, and verification 
automatically.
Type-safe abstractions wrap webauthn4j's Java APIs in idiomatic Scala, providing better type safety and reducing the 
risk of implementation errors.

### Standardized Implementation
Implements WebAuthn security requirements correctly (challenge generation, origin validation, credential storage) 
following industry standards.
The verification action can be composed with other Play action builders, fitting naturally into existing authentication 
workflows.

### Reduced Development Time
Instead of writing controllers, challenge management, and credential verification from scratch, you implement only your 
storage layer.
Spend time on your app-specific requirements rather than learning WebAuthn protocol intricacies.

## Structure

The library provides a [PasskeyAuth](src/main/scala/com/gu/playpasskeyauth/PasskeyAuth.scala) class, which gives you:
1. a verification action that can be composed with other action builders
2. a controller that can be included in a Play routes file to perform [standard passkey operations](Passkeys.md).

The library is storage-agnostic.  You must decide how best to store passkey data in your infrastructure.
Consequently, the integration depends on the implementation of some service traits.

## Installation
Add to your `build.sbt`:
```scala
libraryDependencies += "com.gu" %% "play-passkey-auth" % "<version>"
```

## Integration steps

1. Implement a [PasskeyRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyRepository.scala).
2. Implement a [PasskeyChallengeRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyChallengeRepository.scala).
3. Implement a [CreationDataExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithCreationData.scala).
4. Implement an [AuthenticationDataExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithAuthenticationData.scala).
5. Implement a [PasskeyNameExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithCreationData.scala).
6. Pass these as arguments into a [PasskeyAuth](src/main/scala/com/gu/playpasskeyauth/PasskeyAuth.scala).

## Integration examples
 show actual Scala/Play code
 how to handle common failure cases
 how it fits into existing Play apps
