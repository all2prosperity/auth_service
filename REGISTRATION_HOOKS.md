# Registration Hooks Guide

This guide explains how to use registration hooks in the Auth Service module to execute custom business logic when users register.

## Overview

Registration hooks allow you to execute custom code after successful user registration. This is useful for:

- Creating user profiles in other systems
- Sending welcome messages or notifications
- Triggering analytics events
- Updating other database tables
- Integrating with external services
- Custom business logic specific to your application

## Types of Registration

The auth module supports multiple registration methods, and the hook will be called for all of them:

1. **Password Registration** (`method: "email"` or `method: "phone"`)
   - Traditional email/phone + password registration
   - Called via `Register` endpoint

2. **SMS Code Registration** (`method: "sms_code"`)
   - Phone number + SMS verification code + password
   - Called via `CompleteCodeRegister` endpoint

3. **Code Login (Auto-Registration)** (`method: "email_code"` or `method: "sms_code"`)
   - First-time login with email/SMS code automatically creates user
   - Called via `CompleteCodeLogin` endpoint

## Hook Function Signature

```go
type UserRegistrationInfo struct {
    UserID      string     // Unique user identifier
    Email       *string    // User email (may be nil)
    PhoneNumber *string    // User phone number (may be nil)
    Roles       []string   // User roles (typically ["user"])
    CreatedAt   time.Time  // Registration timestamp
    Method      string     // Registration method
}

type RegistrationHook func(ctx context.Context, user *UserRegistrationInfo) error
```

## Setup Methods

### Method 1: During Module Initialization

```go
import auth "github.com/all2prosperity/auth_service"

func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    // Your custom logic here
    log.Printf("New user registered: %s via %s", user.UserID, user.Method)
    return nil
}

func main() {
    hooks := &auth.AuthHooks{
        OnRegistered: onUserRegistered,
    }

    authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
        DB:    db,
        Hooks: hooks,
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

### Method 2: After Module Initialization

```go
authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
    DB: db,
})
if err != nil {
    log.Fatal(err)
}

// Set hook after initialization
authModule.SetRegistrationHook(onUserRegistered)
```

### Method 3: Update All Hooks

```go
hooks := &auth.AuthHooks{
    OnRegistered: onUserRegistered,
    // Future hooks can be added here
}

authModule.SetHooks(hooks)
```

## Hook Execution Details

### Asynchronous Execution
- Hooks are executed in a **separate goroutine** to avoid blocking the registration response
- Registration response is sent immediately to the client
- Hook failures are logged but don't affect the registration success

### Error Handling
- If a hook returns an error, it's logged but doesn't roll back the registration
- The user is successfully registered regardless of hook execution results
- Design your hooks to be resilient and handle failures gracefully

### Context
- The hook receives the same context as the registration request
- Use this context for cancellation, timeouts, and request-scoped values
- Be mindful of context cancellation in long-running hook operations

## Best Practices

### 1. Keep Hooks Fast and Lightweight
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    // ✅ Good: Quick operations
    log.Printf("User registered: %s", user.UserID)
    
    // ✅ Good: Non-blocking operations
    go sendWelcomeEmail(user.Email)
    
    return nil
}
```

### 2. Handle Errors Gracefully
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    if err := createUserProfile(user); err != nil {
        // Log error but don't fail the registration
        log.Printf("Failed to create user profile: %v", err)
        // Optionally: queue for retry, send to error tracking, etc.
    }
    return nil
}
```

### 3. Use Context for Timeouts
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    // Create timeout context for external calls
    timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    
    return callExternalAPI(timeoutCtx, user)
}
```

### 4. Differentiate by Registration Method
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    switch user.Method {
    case "email", "phone":
        // Password-based registration
        return handlePasswordRegistration(user)
    case "sms_code":
        // SMS verification registration
        return handleSMSRegistration(user)
    case "email_code", "sms_code":
        // Code-based auto-registration
        return handleCodeRegistration(user)
    default:
        log.Printf("Unknown registration method: %s", user.Method)
        return nil
    }
}
```

## Example Use Cases

### 1. User Profile Creation
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    profile := &UserProfile{
        UserID:    user.UserID,
        Email:     user.Email,
        Phone:     user.PhoneNumber,
        CreatedAt: user.CreatedAt,
    }
    
    return userProfileDB.Create(profile)
}
```

### 2. Analytics and Tracking
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    event := analytics.Event{
        Type:   "user_registered",
        UserID: user.UserID,
        Properties: map[string]interface{}{
            "method":           user.Method,
            "has_email":        user.Email != nil,
            "has_phone":        user.PhoneNumber != nil,
            "registration_time": user.CreatedAt,
        },
    }
    
    return analytics.Track(ctx, event)
}
```

### 3. Welcome Communications
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    if user.Email != nil {
        go sendWelcomeEmail(*user.Email, user.UserID)
    }
    
    if user.PhoneNumber != nil {
        go sendWelcomeSMS(*user.PhoneNumber, user.UserID)
    }
    
    return nil
}
```

### 4. External System Integration
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    // Add user to CRM system
    crmUser := CRMUser{
        ID:       user.UserID,
        Email:    user.Email,
        Phone:    user.PhoneNumber,
        Source:   "auth_service",
        Method:   user.Method,
    }
    
    return crmClient.CreateUser(ctx, crmUser)
}
```

## Debugging and Monitoring

### Logging
```go
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    start := time.Now()
    defer func() {
        log.Printf("Registration hook completed in %v for user %s", 
            time.Since(start), user.UserID)
    }()
    
    // Your logic here
    return nil
}
```

### Metrics
```go
var (
    hookDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "auth_registration_hook_duration_seconds",
            Help: "Duration of registration hook execution",
        },
        []string{"method", "status"},
    )
)

func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
    start := time.Now()
    status := "success"
    
    defer func() {
        hookDuration.WithLabelValues(user.Method, status).Observe(time.Since(start).Seconds())
    }()
    
    if err := doSomething(user); err != nil {
        status = "error"
        return err
    }
    
    return nil
}
```

## Testing

### Unit Testing
```go
func TestRegistrationHook(t *testing.T) {
    user := &auth.UserRegistrationInfo{
        UserID:    "test-user-123",
        Email:     stringPtr("test@example.com"),
        Method:    "email",
        CreatedAt: time.Now(),
    }
    
    err := onUserRegistered(context.Background(), user)
    assert.NoError(t, err)
    
    // Verify your business logic was executed
    // e.g., check database, mock calls, etc.
}
```

### Integration Testing
```go
func TestAuthModuleWithHooks(t *testing.T) {
    hookCalled := false
    
    testHook := func(ctx context.Context, user *auth.UserRegistrationInfo) error {
        hookCalled = true
        return nil
    }
    
    authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
        DB: testDB,
        Hooks: &auth.AuthHooks{
            OnRegistered: testHook,
        },
    })
    require.NoError(t, err)
    
    // Perform registration via API
    // ... registration test code ...
    
    // Verify hook was called
    assert.True(t, hookCalled)
}
```

## Migration Guide

If you're upgrading from a version without hooks:

1. **No Breaking Changes**: Existing code continues to work without modification
2. **Optional Feature**: Hooks are completely optional
3. **Gradual Adoption**: Add hooks when you need custom registration logic

## Future Extensions

The hook system is designed to be extensible. Future versions may include:

- Login hooks
- Password reset hooks
- User update hooks
- Token refresh hooks
- Account lock/unlock hooks

The pattern established with registration hooks will be consistent across all future hook types.