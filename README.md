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

## Structure

This library provides a [PasskeyAuth](src/main/scala/com/gu/playpasskeyauth/PasskeyAuth.scala) class, which gives you:
1. a verification action that can be composed with other action builders
2. a controller that can be included in a Play routes file to perform [standard passkey operations](Passkeys.md).

The library is storage-agnostic.  You must decide how best to store passkey data in your infrastructure.
Consequently, the integration depends on the implementation of some service traits.

## Installation
Add to your `build.sbt`:
```scala
libraryDependencies += "com.gu" %% "play-passkey-auth" % "<version>"
```

## Quick start

See the [example](example/) directory for a complete, working Play application that demonstrates:
- Registering new passkeys
- Authenticating with passkeys
- Managing (listing and deleting) passkeys
- In-memory repository implementations

Run the example:
```bash
sbt "project example" run
```

Then open http://localhost:9000 in your browser.

## Integration steps

1. Define a [PasskeyUser](src/main/scala/com/gu/playpasskeyauth/models/PasskeyUser.scala) instance for your user type.
2. Implement a [PasskeyRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyRepository.scala).
3. Implement a [PasskeyChallengeRepository](src/main/scala/com/gu/playpasskeyauth/services/PasskeyChallengeRepository.scala).
4. Implement a [CreationDataExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithCreationData.scala).
5. Implement an [AuthenticationDataExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithAuthenticationData.scala).
6. Implement a [PasskeyNameExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithCreationData.scala).
7. Implement a [UserExtractor](src/main/scala/com/gu/playpasskeyauth/web/RequestWithUser.scala).
8. Pass these as arguments into a [PasskeyAuth](src/main/scala/com/gu/playpasskeyauth/PasskeyAuth.scala).

## Integration examples
 show actual Scala/Play code
 how to handle common failure cases
 how it fits into existing Play apps
