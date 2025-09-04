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

	auth "github.com/all2prosperity/auth_service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Example: Use auth service as a module in your existing application

	// Setup your own database connection
	dsn := "host=localhost port=5432 user=youruser password=yourpass dbname=yourdb sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Initialize auth module with your database
	authModule, err := auth.NewAuthModule(auth.AuthModuleConfig{
		DB:             db,
		ConsoleEnabled: true,
		Logger:         log.Default(),
	})
	if err != nil {
		log.Fatal("Failed to initialize auth module:", err)
	}
	defer authModule.Close()

	// Create your main router
	router := chi.NewRouter()

	// Add your middleware
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

	// ConnectRPC preflight/CORS helper for JSON/Connect transport
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

	// Add your own routes
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Your Application with Auth Service v0.4")
	})

	// Health check that includes auth module health
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

	// Your other business logic routes
	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/products", getProducts)
		r.Get("/orders", getOrders)
		r.Get("/profile", getProfile) // This might use auth module's handler for user info
		// ... other routes
	})

	// Start auth module cleanup routine
	authModule.StartCleanupRoutine()

	// Start server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      h2c.NewHandler(router, &http2.Server{}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Println("Server starting on port 8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

// Example business logic handlers
func getProducts(w http.ResponseWriter, r *http.Request) {
	// Your business logic here
	// You can access user information through auth middleware if needed
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"products": [{"id": 1, "name": "Product 1"}, {"id": 2, "name": "Product 2"}]}`)
}

func getOrders(w http.ResponseWriter, r *http.Request) {
	// Your business logic here
	// You might want to extract user ID from JWT token for user-specific orders
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"orders": [{"id": 1, "product_id": 1, "quantity": 2}]}`)
}

func getProfile(w http.ResponseWriter, r *http.Request) {
	// Example of how you might integrate with auth module
	// In a real application, you'd extract user info from the JWT token
	// and possibly use the auth module's user DAO to get additional user data

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	// Here you would validate the token using the auth module's JWT service
	// For now, just return a mock response
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"user_id": "user123", "email": "user@example.com", "roles": ["user"]}`)
}

// Advanced example: Using auth module's database and handler directly
func advancedIntegrationExample() {
	// You can also access the auth module's internal components for advanced usage

	// Get database instance
	// db := authModule.GetDatabase()

	// Get auth handler for direct access
	// handler := authModule.GetHandler()

	// Get configuration
	// config := authModule.GetConfig()

	// Use these for custom business logic that integrates deeply with auth
}
