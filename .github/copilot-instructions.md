# Agent Instructions for play-passkeyauth

This file provides machine-readable context for AI coding agents working in this repository.
Read `CONTRIBUTING.md` for the human-oriented narrative. This file records facts that are
useful primarily as unambiguous reference for agents.

---

## Repository identity

- **Library**: `com.gu:play-passkeyauth`
- **Language**: Scala 3.3.x (LTS)
- **Framework**: Play Framework 3.0.x
- **Build tool**: sbt
- **Effect type**: `scala.concurrent.Future` — no IO monad, no Cats Effect, no ZIO
- **WebAuthn implementation**: WebAuthn4J (`com.webauthn4j:webauthn4j-core`)

---

## Package layout (canonical paths)

```
com.gu.playpasskeyauth                          root package
com.gu.playpasskeyauth.PasskeyAuth              main wiring class — consumers instantiate this
com.gu.playpasskeyauth.PasskeyAuthContext        config bundle supplied by consumer
com.gu.playpasskeyauth.controllers.PasskeyController  HTTP controller
com.gu.playpasskeyauth.filters.PasskeyVerificationFilter  ActionFilter for step-up auth
com.gu.playpasskeyauth.models.*                 pure domain types and config
com.gu.playpasskeyauth.services.*               effectful service layer
com.gu.playpasskeyauth.web.*                    Play action refiners and wrapped requests
```

---

## Key types and their roles

| Type | Kind | Role |
|---|---|---|
| `PasskeyAuth[U, B]` | `class` | Top-level wiring; call `.controller()` and `.verificationAction()` |
| `PasskeyAuthContext[U, B]` | `case class` | Consumer-supplied config: action builder, extractors (all extractors take `Request[B]`) |
| `PasskeyUser[U]` | `trait` (typeclass) | Bridge between consumer's user type and library; companion has `apply` summoner; requires `id: UserId` and `displayName: String` extension methods |
| `PasskeyVerificationService` | `trait` | Public service API; all methods return `Future[A]` |
| `PasskeyVerificationServiceImpl` | `class` | Private-to-package implementation; not part of public API |
| `PasskeyRepository` | `trait` | Consumer-implemented; 4 methods: `get`, `list`, `upsert`, `delete` |
| `PasskeyChallengeRepository` | `trait` | Consumer-implemented; 3 methods (`load`, `insert`, `delete`) with `ChallengeType` discriminator |
| `ChallengeType` | `enum` | `Registration` or `Authentication`; used by `PasskeyChallengeRepository` |
| `PasskeyError` | `enum` | Domain error cases: `InvalidName`, `DuplicateName`, `PasskeyNotFound`, `ChallengeExpired` |
| `PasskeyException` | `final case class extends Exception` | Wraps `PasskeyError`; used to signal expected domain failures in `Future` |
| `Passkey` | `case class` | Stored credential: `id`, `name`, `credentialRecord`, `createdAt`, `lastUsedAt`, `signCount`, `aaguid` |
| `PasskeyId` | `case class` | Type-safe `Array[Byte]` wrapper; custom `equals`/`hashCode`; serialises as base64url |
| `PasskeyName` | `case class` (private ctor) | Validated name; construct via `PasskeyName.validate` or `PasskeyName.apply` |
| `UserId` | `case class` | Type-safe user ID string; rejects blank or padded values |
| `HostApp` | `case class` | Relying party: `name`, `uri`; derives `host` and `origin`; enforces https (localhost may use http) |
| `WebAuthnConfig` | `case class` | Pure WebAuthn options; default via `WebAuthnConfig.default`; customise via `withTimeout`, `withAttestation`, `withoutUserVerification`, `withTransports` |
| `JsonEncodings` | `object` | `given Writes[…]` and `given Reads[…]` instances + Jackson↔Play JSON bridge |
| `RequestWithUser[U,A]` | `case class extends WrappedRequest` | After `UserAction` refiner |
| `RequestWithCreationData[U,A]` | `case class extends WrappedRequest` | After `CreationDataAction` refiner |
| `RequestWithAuthenticationData[U,A]` | `case class extends WrappedRequest` | After `AuthenticationDataAction` refiner |

---

## Action pipeline composition

```
ctx.actionBuilder                            ActionBuilder[Request, B]
  .andThen(UserAction(ctx.userExtractor))    → ActionBuilder[[A]=>>RequestWithUser[U,A], B]
    .andThen(CreationDataAction(…))          → ActionBuilder[[A]=>>RequestWithCreationData[U,A], B]
    .andThen(AuthenticationDataAction(…))    → ActionBuilder[[A]=>>RequestWithAuthenticationData[U,A], B]
      .andThen(PasskeyVerificationFilter(…)) → ActionBuilder[[A]=>>RequestWithAuthenticationData[U,A], B]
```

The type lambda syntax `[A] =>> RequestWithUser[U, A]` is Scala 3 canonical for partially-applied type
constructors used as `ActionRefiner` type arguments.

---

## Invariants that must never be broken

1. **`models/` is pure**: no `Future`, no I/O, no side effects.
2. **`services/` returns `Future`**: never return bare values for operations that touch storage or external libs.
3. **Domain errors use `PasskeyException`**: wrap `PasskeyError` in `PasskeyException` and fail the `Future`.
   Do not use `Either` at the service boundary.
4. **`PasskeyVerificationServiceImpl` is `private[playpasskeyauth]`**: do not expose it in the public API.
5. **Action refiners return `Future.successful`** for synchronous extraction; they never block.
6. **Error recovery is in `PasskeyController.apiResponse`**: do not add `recover` blocks in individual action methods.
7. **`-Werror` is set**: every PR must compile with zero warnings.
8. **`scalafmtOnCompile := true`**: code is auto-formatted; do not fight the formatter.
9. **`-no-indent`**: always use braces; never rely on significant indentation.
10. **The `example/` app must always compile and work**: any public API change must be applied to the example
    in the same edit. Update `PasskeyModule`, the in-memory repositories, the example controller, and
    `example/conf/routes` as needed so that `sbt "project example" run` remains functional.

---

## Test conventions

- **Framework**: ScalaTest (`AnyFlatSpec` + `Matchers`) + ScalaCheck (`ScalaCheckPropertyChecks`)
- **Dependencies**: `scalatestplus-play`, `scalatestplus-scalacheck-1-18`
- **Test source root**: `src/test/scala/com/gu/playpasskeyauth/`
- **Mirror structure**: test packages match main packages exactly.
- **Property tests**: use `forAll` with named generators defined in companion `object SpecName`.
- **No mocking framework** is used. Pure model tests need none; service impl tests should use real or
  in-memory implementations where possible.
- **One assertion per behaviour**: do not restate the same assertion in multiple test cases.

---

## Build commands

```bash
sbt test                   # compile + run all tests
sbt scalafmt               # format (also runs on compile)
sbt dependencyList         # inspect resolved transitive deps
sbt "project example" run  # run the example Play application
```

---

## Common patterns

### Composing sequential `Future` steps (service layer)

```scala
for {
  existing <- passkeyRepo.list(userId)
  challenge <- challengeRepo.load(userId, ChallengeType.Registration)
  result <- Future.fromTry(Try(expensiveJavaCall()))
  _ <- passkeyRepo.upsert(userId, buildPasskey(result))
} yield result
```

### Lifting a validated value into `Future`

```scala
PasskeyName.validate(raw) match {
  case Right(name) => Future.successful(name)
  case Left(err)   => Future.failed(PasskeyException(PasskeyError.InvalidName(err)))
}
```

### Defining a `PasskeyUser` typeclass instance (consumer code)

```scala
case class MyUser(email: String, displayName: String)

given PasskeyUser[MyUser] with {
  extension (u: MyUser) {
    def id: UserId          = UserId(u.email)
    def displayName: String = u.displayName
  }
}
```

### Wiring `PasskeyAuth` (consumer code)

```scala
import models.MyUser.given  // brings PasskeyUser[MyUser] into scope

val ctx = PasskeyAuthContext[MyUser, AnyContent](
  actionBuilder               = defaultActionBuilder,
  userExtractor               = req => req.attrs(UserKey),
  creationDataExtractor       = req => req.body.asJson.flatMap(j => (j \ "credential").asOpt[JsValue]),
  authenticationDataExtractor = req => req.body.asJson.flatMap(j => (j \ "assertion").asOpt[JsValue]),
  passkeyNameExtractor        = req => req.body.asJson.flatMap(j => (j \ "name").asOpt[String])
)

val passkeyAuth = new PasskeyAuth[MyUser, AnyContent](
  cc, hostApp, ctx, passkeyRepo, challengeRepo, routes.MyController.index()
)
```

---

## What NOT to do

- Do not add `cats`, `zio`, `monix`, or any other effect library — `Future` is intentional.
- Do not expose `PasskeyVerificationServiceImpl` as part of the public API.
- Do not add logic to action refiners beyond extraction and wrapping.
- Do not add `recover` inside individual controller action methods — use `apiResponse`.
- Do not use `implicit` keyword — use `given`/`using` (Scala 3).
- Do not use `sealed trait` + `case class` where a Scala 3 `enum` suffices.
- Do not add dependencies to `root` that are not strictly required; the example sub-project is the place for extras.
- Do not implement `PasskeyRepository` or `PasskeyChallengeRepository` in the library itself — these are
  consumer responsibilities.
- Do not block the calling thread in any `Future`-returning method.

---

## Dependency notes

The `safeTransitiveDependencies` block in `build.sbt` pins Jackson versions to prevent Play and WebAuthn4J from
pulling in conflicting older versions. When adding or upgrading dependencies, run `sbt dependencyList` and verify
no earlier Jackson version appears.
