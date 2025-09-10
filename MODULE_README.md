# Auth Service Module

A complete authentication service that can be used both as a standalone service and as a module in other Go applications.

## Overview

This auth service provides:
- User registration/login (email/phone/password)
- Email/SMS verification-based login
- JWT token management (access + refresh)
- Password reset via email/SMS
- Account lock/unlock
- Audit logging
- Admin console interface

## Features

- **Dual Usage**: Can run as standalone service or integrate as module
- **Flexible Database**: Support for external database connections
- **Secure**: Argon2id password hashing, JWT blacklisting, rate limiting
- **Scalable**: Stateless JWT tokens, connection pooling
- **Observable**: Prometheus metrics, structured logging
- **Configurable**: YAML/environment variable configuration

## Usage Modes

### 1. Standalone Service

Run as an independent authentication server:

```bash
# Setup
cd auth_service/srv
go mod download

# Configure database
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_USER=auth_user
export DATABASE_PASSWORD=your_password
export DATABASE_NAME=auth_service

# Run standalone server
go run cmd/server/main.go
```

The service will start on the configured port and provide:
- Authentication APIs via ConnectRPC at `/auth.v1.AuthService/*`
- Admin console at `/admin/*`
- Health check at `/health`
- Metrics at `/metrics`

### 2. Module Integration

Use as a module in your existing Go application:

#### Installation

Add to your `go.mod`:

```bash
go mod edit -require github.com/your-org/auth_service@latest
go mod tidy
```

#### Basic Usage

```go
package main

import (
    "log"
    auth "github.com/all2prosperity/auth_service"
    "github.com/go-chi/chi/v5"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

func main() {
    // Setup your database connection
    db, err := gorm.Open(postgres.Open("your-dsn"), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }

    // Initialize auth module
    authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
        DB: db,
        ConsoleEnabled: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer authModule.Close()

    // Create router and register auth routes
    router := chi.NewRouter()
    authModule.RegisterRoutes(router)

    // Register console routes (optional)
    consoleMux := http.NewServeMux()
    authModule.RegisterConsoleRoutes(consoleMux)
    router.Mount("/admin", consoleMux)

    // Add your business logic routes
    router.Get("/api/products", yourHandler)

    // Start cleanup routine
    authModule.StartCleanupRoutine()

    // Start server
    http.ListenAndServe(":8080", router)
}
```

#### Configuration Options

```go
type AuthModuleConfig struct {
    // Database connection (required - choose one)
    DB    *gorm.DB     // Use existing GORM instance
    SQLDB *sql.DB      // Use existing sql.DB instance
    
    // Optional configurations
    Redis          *redis.Client    // Redis client (will create if not provided)
    Config         *config.Config   // Auth config (will load default if not provided)
    Logger         *log.Logger      // Standard logger
    ZapLogger      *zap.Logger      // Zap logger
    ZerologLogger  *zerolog.Logger  // Zerolog logger
    ConsoleEnabled bool             // Enable admin console (default: true)
    Hooks          *AuthHooks       // Event hooks for custom business logic
}
```

#### Advanced Usage

```go
// Access internal components for advanced integration
db := authModule.GetDatabase()
handler := authModule.GetHandler()
config := authModule.GetConfig()

// Custom health check
router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
    if err := authModule.Health(); err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
})
```

#### Registration Hooks

Registration hooks allow you to execute custom business logic after successful user registration:

```go
// Define your registration hook
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    log.Printf("New user registered: %s via %s", user.UserID, user.Method)
    
    // Your custom business logic here:
    // - Create user profile in other systems
    // - Send welcome notifications
    // - Trigger analytics events
    // - Update other database tables
    
    return createUserProfile(user)
}

// Method 1: Set hooks during initialization
hooks := &auth.AuthHooks{
    OnRegistered: onUserRegistered,
}

authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
    DB: db,
    Hooks: hooks,
})

// Method 2: Set hooks after initialization
authModule.SetRegistrationHook(onUserRegistered)
```

The hook receives detailed user information:
```go
type UserRegistrationInfo struct {
    UserID      string     // Unique user identifier
    Email       *string    // User email (may be nil)
    PhoneNumber *string    // User phone number (may be nil)
    Roles       []string   // User roles
    CreatedAt   time.Time  // Registration timestamp
    Method      string     // "email", "phone", "sms_code", etc.
}
```

**Important Notes:**
- Hooks are executed asynchronously to avoid blocking the registration response
- Hook failures are logged but don't affect registration success
- Design hooks to be fast and resilient

For detailed documentation, see [REGISTRATION_HOOKS.md](REGISTRATION_HOOKS.md).

## API Endpoints

When you register the auth module routes, the following endpoints become available:

### Authentication
- `POST /auth.v1.AuthService/Register` - User registration
- `POST /auth.v1.AuthService/Login` - User login with password
- `POST /auth.v1.AuthService/RefreshToken` - Token refresh
- `POST /auth.v1.AuthService/Logout` - User logout
- `GET /auth.v1.AuthService/GetMe` - Get current user info

### Password Reset
- `POST /auth.v1.AuthService/StartPasswordReset` - Start password reset
- `POST /auth.v1.AuthService/CompletePasswordReset` - Complete password reset

### Code-based Login
- `POST /auth.v1.AuthService/StartCodeLogin` - Start code-based login
- `POST /auth.v1.AuthService/CompleteCodeLogin` - Complete code-based login

### Code-based Registration
- `POST /auth.v1.AuthService/StartCodeRegister` - Start SMS registration
- `POST /auth.v1.AuthService/CompleteCodeRegister` - Complete SMS registration

### Admin Console (if enabled)
- `/admin/*` - Admin interface for user management

## Configuration

### Environment Variables

```bash
# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=auth_user
DATABASE_PASSWORD=your_password
DATABASE_NAME=auth_service
DATABASE_SSL_MODE=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# JWT
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
JWT_ACCESS_EXPIRES=15m
JWT_REFRESH_EXPIRES=7d

# SMTP (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=your_email@gmail.com

# SMS (optional)
SMS_PROVIDER=twilio
SMS_ACCOUNT_SID=your_twilio_sid
SMS_AUTH_TOKEN=your_twilio_token
SMS_FROM_NUMBER=+1234567890

# Server
SERVER_PORT=8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=60s

# Console
CONSOLE_ENABLED=true
```

### YAML Configuration

You can also use a `config.yaml` file:

```yaml
database:
  host: localhost
  port: 5432
  user: auth_user
  password: your_password
  dbname: auth_service
  sslmode: disable

redis:
  host: localhost
  port: 6379
  password: ""
  db: 0

jwt:
  access_secret: your_access_secret
  refresh_secret: your_refresh_secret
  access_expires: 15m
  refresh_expires: 7d

smtp:
  host: smtp.gmail.com
  port: 587
  username: your_email@gmail.com
  password: your_app_password
  from: your_email@gmail.com

sms:
  provider: twilio
  account_sid: your_twilio_sid
  auth_token: your_twilio_token
  from_number: "+1234567890"

server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 60s
```

## Requirements

- Go 1.23+
- PostgreSQL 15+
- Redis (optional, for registration codes)
- SMTP server (optional, for email verification)
- Twilio account (optional, for SMS verification)

## Dependencies

Major dependencies include:
- `gorm.io/gorm` - ORM for database operations
- `connectrpc.com/connect` - RPC framework
- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/golang-jwt/jwt/v5` - JWT tokens
- `golang.org/x/crypto` - Argon2 password hashing
- `github.com/go-redis/redis/v8` - Redis client
- `go.uber.org/zap` - Structured logging

See [go.mod](go.mod) for the complete list.

## Development

### Database Setup

```sql
CREATE DATABASE auth_service;
CREATE USER auth_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
```

### Build and Run

```bash
# Standalone service
go run cmd/server/main.go

# Build binary
go build -o auth_service cmd/server/main.go
```

### Migrations

```bash
# Apply migrations
go run cmd/migrate/main.go -action=up

# Rollback migrations
go run cmd/migrate/main.go -action=down

# Seed data
go run cmd/migrate/main.go -action=seed
```

### Testing

```bash
# Run tests
go test ./...

# Run with coverage
go test -cover ./...
```

## Architecture

- **Layered Architecture**: Handlers → Services → DAOs → Models
- **Dependency Injection**: Loose coupling between components
- **Repository Pattern**: DAO layer abstracts database operations
- **Strategy Pattern**: Different authentication channels (email, phone)
- **Middleware Pattern**: Logging, authentication, rate limiting

## Security Features

- **Password Hashing**: Argon2id with salt
- **JWT Security**: Access/refresh token pattern with blacklisting
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Complete audit trail of user actions
- **Input Validation**: Comprehensive request validation
- **CORS**: Configurable cross-origin resource sharing

## Deployment

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o auth_service main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth_service .
CMD ["./auth_service"]
```

### Environment Variables

Ensure all required environment variables are set in production:
- Strong JWT secrets
- Secure database credentials  
- Proper CORS configuration
- Production logging levels

## Monitoring

- **Health Checks**: `/health` endpoint for service health
- **Metrics**: Prometheus metrics at `/metrics`
- **Logging**: Structured logging with configurable levels
- **Audit Trail**: Complete user action logging

## Troubleshooting

### Common Issues

1. **Database Connection**: Verify PostgreSQL is running and credentials are correct
2. **Redis Connection**: Check Redis configuration if using registration codes
3. **JWT Tokens**: Ensure secrets are properly configured and not expired
4. **Email/SMS**: Verify SMTP/Twilio credentials for verification features

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=debug
```

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]