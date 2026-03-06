# Contributing to play-passkeyauth

## Overview

`play-passkeyauth` is a Scala 3 library that integrates WebAuthn/passkey authentication into Play Framework 3
applications. It wraps the [WebAuthn4J](https://webauthn4j.github.io/webauthn4j/en/) Java library behind idiomatic
Scala and Play abstractions.

The library is intentionally small and focused. It does **not** provide storage implementations — consumers supply
their own `PasskeyRepository` and `PasskeyChallengeRepository` for their chosen persistence backend.

---

## Code Structure

```
com.gu.playpasskeyauth              Top-level wiring: PasskeyAuth and PasskeyAuthContext
com.gu.playpasskeyauth.controllers  HTTP layer: registration and management endpoints
com.gu.playpasskeyauth.filters      Action filter for step-up passkey verification
com.gu.playpasskeyauth.models       Pure domain types, validation and immutable config
com.gu.playpasskeyauth.services     Effectful service layer: repositories and verification
com.gu.playpasskeyauth.web          Play action refiners and wrapped request types

example/                        Runnable Play app demonstrating a complete integration
src/test/…models/               Unit and property-based tests for domain models
src/test/…services/             Unit tests for service-layer types
```

### Layer responsibilities

| Layer | Package | Responsibility |
|---|---|---|
| Entry point | (root) | `PasskeyAuth` wires all components together; `PasskeyAuthContext` bundles consumer config |
| HTTP | `controllers`, `filters`, `web` | Play action pipeline; no business logic |
| Domain | `models` | Pure data types, validation, and immutable config; no I/O |
| Service | `services` | Orchestrates I/O (repository calls, WebAuthn4J verification) via `Future` |

---

## Design Principles

### 1. Separation of pure and effectful code

Pure code and effectful code are kept in separate layers and separate files.

- **`models/`** contains only pure values and validation logic. Nothing in `models/` touches `Future`, repositories,
  or any I/O. Methods are total or raise `IllegalArgumentException` at construction time on clearly invalid input.
- **`services/`** is where effects live. `PasskeyVerificationServiceImpl` orchestrates `Future`-returning repository
  calls and WebAuthn4J verification, composing them with `for`/`yield`.
- **`web/`** action refiners are thin adapters that lift synchronous extraction functions into `Future` using
  `Future.successful`. They contain no business logic.

The rule of thumb: if a method or class can be tested without a `Future`, it belongs in `models/`.

### 2. Effects are expressed as plain `scala.concurrent.Future`

The library uses `Future` as the sole effect type — no IO monads, no effect stacks. This keeps the API accessible
to all Play applications without requiring extra dependencies or concepts.

- All effectful operations return `Future[A]`.
- Failures are signalled by failing the `Future` (not by wrapping in `Either` or similar at the service boundary).
- `PasskeyException(PasskeyError)` is the domain failure type; unexpected errors propagate as raw exceptions.
- Effects are initiated asynchronously as early as possible. Play's `async` action helpers ensure the calling thread
  is never blocked.

### 3. Play action pipeline

The request lifecycle is modelled as a composed Play action pipeline:

```
ActionBuilder[Request]
  └─ andThen UserAction         →  RequestWithUser[U]
       └─ andThen CreationDataAction   →  RequestWithCreationData[U]  (registration)
       └─ andThen AuthenticationDataAction → RequestWithAuthenticationData[U]  (auth)
            └─ andThen PasskeyVerificationFilter   (step-up verification)
```

Each step is a focused `ActionRefiner` or `ActionFilter` that does one thing. Controllers and filters contain no
parsing or domain logic beyond what is delegated to the service layer.

### 4. Scala 3 idioms

- Use `given`/`using` for typeclass evidence (see `PasskeyUser`). Avoid implicit conversions.
- Prefer `enum` over `sealed trait` hierarchies for sum types with known cases (see `PasskeyError`,
  `PasskeyName.ValidationError`).
- Use Scala 3 `extension` methods inside typeclass `given` instances (see `PasskeyUser`).
- Use higher-kinded type lambdas (`[A] =>> RequestWithUser[U, A]`) for refiner types — this is the canonical Scala 3
  approach for partially-applied type constructors.
- No `-indent` style: always use explicit braces (`-no-indent` is set in `scalacOptions`). Scalafmt enforces
  formatting on compile.

### 5. Play best practices

- Controllers extend `AbstractController` and inject `ControllerComponents`.
- Actions use `parse.empty` (i.e. `Action[Unit]`) wherever the body is not needed; this avoids unnecessary body
  parsing.
- JSON responses use Play's `Writes` typeclass via `given` instances in `JsonEncodings`.
- Redirect after POST for registration success (PRG pattern).
- Error recovery is centralised in `PasskeyController.apiResponse` — don't duplicate error-handling logic in
  individual action methods.
- Logging uses Play's `Logging` trait; structured log lines include the action name and user ID.
- The library is designed to be wired via Guice but is not Guice-specific; `PasskeyAuth` is a plain class.

---

## Testing

### Philosophy

- **Coverage should be meaningful rather than mechanical.** Aim for tests that document behaviour and catch regressions in
  the key invariants of each unit, rather than chasing line coverage for its own sake.
- **No overlaps, no gaps.** Each behaviour should be asserted in exactly one place. Do not duplicate assertions
  across multiple test cases; do not leave domain rules untested.
- **Pure code is the easiest to test.** Write tests against the model layer first. These tests are fast, deterministic,
  and require no mocking.

### Property-based testing

Use [ScalaCheck](https://scalacheck.org/) (via `scalatestplus-scalacheck`) for any property that should hold across
a space of inputs:

- Validation rules (e.g., `PasskeyName.validate` accepts all valid names, rejects all names containing dangerous
  characters).
- Round-trip properties (e.g., `PasskeyId.fromBase64Url(id.toBase64Url) == id`).
- Structural invariants (e.g., `HostApp` accepts any valid HTTPS domain).

Place generators in companion objects of the spec class (e.g., `PasskeyNameSpec` / `HostAppSpec`) so they are
reusable and clearly scoped.

```scala
// Good — property-based
it should "reject any name longer than 255 characters" in {
  forAll(Gen.chooseNum(256, 1000)) { length =>
    PasskeyName.validate("a" * length).left.value shouldBe PasskeyName.ValidationError.TooLong(255)
  }
}

// Also good — targeted example for a specific edge case
it should "accept name at maximum length" in {
  PasskeyName.validate("a" * 255).value.value shouldBe "a" * 255
}
```

### Example-based testing

Use targeted examples for:

- Specific boundary values (empty string, max length, known dangerous characters).
- Error messages (the exact wording is a contract; test it explicitly).
- Behaviour that is hard to express as a generator (e.g., `require` throws on null vs. empty).

### Test structure

- Use `AnyFlatSpec` with `Matchers` as the base for all spec classes.
- Mix in `ScalaCheckPropertyChecks` when property tests are needed.
- Group tests by subject with `"Subject" should "behaviour"` / `it should "…"`.
- Mirror the main source tree: `src/test/scala/com/gu/playpasskeyauth/models/` tests
  `src/main/scala/com/gu/playpasskeyauth/models/`, etc.

### What to test

| Layer | Test focus |
|---|---|
| `models/` | All validation rules, boundary conditions, `require` guards, helper methods, error messages |
| `services/` | Domain error types and their messages; error mapping |
| `controllers/`, `filters/` | Integration via Play's test helpers if the logic warrants it |

> The `PasskeyVerificationServiceImpl` delegates the heavy lifting to WebAuthn4J and the repository interfaces. Its
> correctness is best covered by integration tests against real implementations rather than by mocking WebAuthn4J.

---

## Making Changes

### Adding a new model field or validation rule

1. Update the model in `models/`.
2. Add or update tests in the corresponding spec. If the rule applies to a range of inputs, use a property-based test.
3. Ensure `PasskeyVerificationServiceImpl` and `PasskeyController` remain consistent.

### Adding a new service operation

1. Add the method signature (with Scaladoc) to `PasskeyVerificationService`.
2. Implement in `PasskeyVerificationServiceImpl` using `for`/`yield` over `Future`.
3. Expose via `PasskeyController` if it needs an HTTP endpoint.
4. Add the route to the example `routes` file.

### Adding a new repository operation

1. Add the method to the relevant repository trait (`PasskeyRepository` or `PasskeyChallengeRepository`).
2. Implement it in the example's in-memory repositories.
3. Document the expected semantics clearly in the trait Scaladoc.

### Keeping the example application current

The `example/` sub-project is the canonical reference integration and must always
compile, run, and demonstrate the full registration and authentication flow correctly.

- **Any change to the library's public API must be reflected in the example immediately**, in the same PR.
  This includes changes to `PasskeyAuth`, `PasskeyAuthContext`, `PasskeyRepository`, `PasskeyChallengeRepository`,
  `HostApp`, or any type that appears in consumer-facing signatures.
- **The example's in-memory repository implementations** (`InMemoryPasskeyRepository`,
  `InMemoryChallengeRepository`) must implement every method of their respective traits. They serve as the
  reference implementation that consumers can adapt.
- **Routes must stay consistent** with the controller. Every endpoint exposed by the example
  `PasskeyController` must have a corresponding entry in `example/conf/routes`, and vice versa.
- **Run the example before merging** any change that touches the HTTP layer, the action pipeline, or the
  wiring in `PasskeyModule`. Use `sbt "project example" run` and verify the flows work end-to-end.
- The example uses `User.demo` as a hardcoded user for simplicity. This is intentional; the example is not a
  full authentication system. Do not add real session management or a database to the example.

### Changing the public API

This library is published. Follow semantic versioning: breaking changes require a major version bump. The
`sbt-version-policy` plugin enforces binary compatibility checks on release.

---

## Build & Tooling

```bash
sbt test          # run all tests
sbt scalafmt      # format all sources (also runs on compile)
sbt dependencyList  # inspect transitive dependencies
```

The `example` sub-project is a runnable Play application:

```bash
cd example
./run.sh
```

- **Scala**: 3.3.x (LTS)
- **Play**: 3.0.x
- **WebAuthn4J**: `webauthn4j-core`
- **Test**: ScalaTest + ScalaCheck via `scalatestplus`
- **Formatting**: Scalafmt (`scalafmtOnCompile := true`)
- **Release**: `sbt-release` + `sbt-version-policy`
