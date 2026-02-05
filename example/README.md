# Play Passkey Auth Example

This is a simple example application demonstrating how to use the `play-passkeyauth` library.

## What it demonstrates

This example shows the simplest possible integration using `PasskeyAuthSimple`:

1. **Registration**: Creating WebAuthn credential creation options and registering new passkeys
2. **Authentication**: Creating WebAuthn credential request options and verifying passkey assertions  
3. **Management**: Listing and deleting registered passkeys

## Architecture

The example consists of:

- **User Model** (`models.User`): A simple user with ID and username
- **Repositories**: In-memory implementations of `PasskeyRepository` and `PasskeyChallengeRepository`
- **Module** (`modules.PasskeyModule`): Guice module that wires up dependencies
- **Controller** (`controllers.PasskeyController`): Handles passkey operations
- **Frontend**: Simple HTML/JavaScript UI that calls the WebAuthn browser APIs

## Running the example

### Prerequisites

- Java 11 or later
- sbt 1.x

### Steps

1. From the root of the repository, run:

```bash
sbt "project example" run
```

2. Open your browser to http://localhost:9000

3. Try the passkey operations:
   - Click "Register New Passkey" to register a new passkey
   - Click "Authenticate" to authenticate with a registered passkey
   - View and delete passkeys in the list

### Using real passkeys

The example works with real WebAuthn authenticators:

- **Hardware Security Keys**: YubiKey, Titan Key, etc.
- **Platform Authenticators**: Touch ID, Face ID, Windows Hello
- **Mobile Devices**: iOS/Android with biometrics

Note: WebAuthn requires HTTPS in production. This example uses `http://localhost` which is allowed for development.

## Code tour

### Key files

#### `app/models/User.scala`
Defines the simple user model and how to extract a `UserId` from it.

#### `app/services/InMemoryPasskeyRepository.scala`
In-memory storage for passkeys. Replace with a database in production.

#### `app/services/InMemoryChallengeRepository.scala`
In-memory storage for challenges. Replace with Redis or similar in production.

#### `app/modules/PasskeyModule.scala`
Guice module that:
- Binds repository implementations
- Creates `PasskeyAuthSimple` with configuration from `application.conf`

#### `app/controllers/PasskeyController.scala`
Main controller demonstrating passkey operations:

```scala
// Creating registration options
passkeyAuth.createOptions(userId, userName)

// Registering a passkey
passkeyAuth.register(userId, passkeyName, credentialJson)

// Creating authentication options
passkeyAuth.authOptions(userId)

// Verifying authentication
passkeyAuth.verify(userId, assertionJson)

// Listing passkeys
passkeyAuth.list(userId)

// Deleting a passkey
passkeyAuth.delete(userId, passkeyId)
```

#### `public/javascripts/passkey.js`
Client-side JavaScript that:
- Calls the server endpoints
- Transforms data between server and browser formats
- Calls `navigator.credentials.create()` and `navigator.credentials.get()`

### Configuration

The configuration is in `conf/application.conf`:

```hocon
passkey.app.name = "Example Passkey App"
passkey.app.origin = "http://localhost:9000"
```

## Adapting for your application

To use this in your own application:

### 1. Define your user model

```scala
case class MyUser(email: String, name: String, ...)

object MyUser:
  given UserIdExtractor[MyUser] = user => UserId(user.email)
```

### 2. Implement repositories

Replace the in-memory implementations with your database:

```scala
class DatabasePasskeyRepository @Inject()(db: Database) extends PasskeyRepository {
  override def get(userId: UserId, passkeyId: PasskeyId): Future[Passkey] = {
    // Query your database
    db.run(passkeys.filter(p => p.userId === userId.value && p.id === passkeyId.value).result.head)
  }
  // ... other methods
}
```

### 3. Extract user

Replace the hardcoded user with some kind of extraction:

```scala
class PasskeyController @Inject()(
  cc: ControllerComponents,
  passkeyAuth: PasskeyAuthSimple
) extends AbstractController(cc) {
  
  private def currentUser(implicit request: Request[_]): Option[User] = ???
  
  def createOptions() = Action.async { implicit request =>
    currentUser match {
      case Some(user) =>
        val userId = UserId.from(user)
        passkeyAuth.createOptions(userId, user.name).map { options =>
          Ok(Json.toJson(options))
        }
      case None =>
        Future.successful(Unauthorized("Not logged in"))
    }
  }
}
```

### 4. Update configuration

In production, use HTTPS:

```hocon
passkey.app.name = "My Production App"
passkey.app.origin = "https://myapp.example.com"
```

## Production considerations

1. **Use HTTPS**: WebAuthn requires HTTPS (except for localhost)
2. **Database Storage**: Replace in-memory repositories with proper database storage
3. **Cache Challenges**: Use Redis or similar for challenge storage with TTL
4. **Error Handling**: Add comprehensive error handling and user-friendly messages
5. **User Sessions**: Integrate with your authentication system
6. **CSRF Protection**: Enable CSRF protection (disabled in this example for simplicity)
7. **Rate Limiting**: Add rate limiting to prevent abuse
8. **Logging**: Add proper logging for security events

## Further reading

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [Passkeys.com](https://www.passkeys.com/)
- [Play Framework Documentation](https://www.playframework.com/documentation)
- [webauthn4j Documentation](https://github.com/webauthn4j/webauthn4j)
