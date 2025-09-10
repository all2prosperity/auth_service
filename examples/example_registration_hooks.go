package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/all2prosperity/auth_service/auth"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Example registration hook that logs user registration and performs custom business logic
func onUserRegistered(ctx context.Context, user *auth.UserRegistrationInfo) error {
	log.Printf("🎉 New user registered!")
	log.Printf("   User ID: %s", user.UserID)
	log.Printf("   Method: %s", user.Method)

	if user.Email != nil {
		log.Printf("   Email: %s", *user.Email)
	}
	if user.PhoneNumber != nil {
		log.Printf("   Phone: %s", *user.PhoneNumber)
	}

	log.Printf("   Roles: %v", user.Roles)
	log.Printf("   Created: %s", user.CreatedAt.Format(time.RFC3339))

	// Example: Custom business logic after user registration
	// This could include:
	// - Adding user to external systems
	// - Sending welcome messages
	// - Creating default user preferences
	// - Triggering analytics events
	// - Updating other database tables

	// Simulate some business logic
	if err := createUserProfile(user); err != nil {
		log.Printf("Failed to create user profile: %v", err)
		return err
	}

	if err := sendWelcomeNotification(user); err != nil {
		log.Printf("Failed to send welcome notification: %v", err)
		// Note: We don't return error here as it's not critical
	}

	return nil
}

// Example business logic functions
func createUserProfile(user *auth.UserRegistrationInfo) error {
	log.Printf("Creating user profile for %s...", user.UserID)
	// TODO: Implement your business logic here
	// e.g., insert into user_profiles table, call external API, etc.
	time.Sleep(100 * time.Millisecond) // simulate some work
	log.Printf("User profile created successfully for %s", user.UserID)
	return nil
}

func sendWelcomeNotification(user *auth.UserRegistrationInfo) error {
	log.Printf("Sending welcome notification to %s...", user.UserID)
	// TODO: Implement your notification logic here
	// e.g., send email, push notification, SMS, etc.
	time.Sleep(50 * time.Millisecond) // simulate some work
	log.Printf("Welcome notification sent to %s", user.UserID)
	return nil
}

func main() {
	log.Println("🚀 Starting auth service with registration hooks example...")

	// Setup your database connection
	dsn := "host=localhost port=5432 user=youruser password=yourpass dbname=yourdb sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Create hooks configuration
	hooks := &auth.AuthHooks{
		OnRegistered: onUserRegistered, // Set the registration callback
	}

	// Initialize auth module with hooks
	authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
		DB:             db,
		ConsoleEnabled: true,
		Hooks:          hooks, // Pass hooks during initialization
	})
	if err != nil {
		log.Fatal("Failed to initialize auth module:", err)
	}
	defer authModule.Close()

	// Alternative way: Set hooks after initialization
	// authModule.SetRegistrationHook(onUserRegistered)

	log.Printf("✅ Auth module initialized with registration hooks")

	// Create router
	router := chi.NewRouter()

	// Add middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.Timeout(60 * time.Second))

	// Add CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Configure properly for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ConnectRPC preflight/CORS helper
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Connect-Protocol-Version, Connect-Timeout-Ms")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Add routes
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Auth Service with Registration Hooks Example - Running on port 8080")
	})

	// Health check
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := authModule.Health(); err != nil {
			http.Error(w, fmt.Sprintf("Auth module unhealthy: %v", err), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Register auth service routes
	authModule.RegisterRoutes(router)

	// Register console admin routes (optional)
	consoleMux := http.NewServeMux()
	authModule.RegisterConsoleRoutes(consoleMux)
	router.Mount("/admin", consoleMux)

	// Start cleanup routine
	authModule.StartCleanupRoutine()

	// Create server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      h2c.NewHandler(router, &http2.Server{}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		log.Println("🌐 Server starting on port 8080")
		log.Println("📝 Try registering a user to see the registration hook in action!")
		log.Println("   Example: POST to /auth.v1.AuthService/CompleteCodeRegister")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("✅ Server exited")
}
