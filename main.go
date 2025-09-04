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

	"auth_service/config"
	"auth_service/dao"
	"auth_service/database"
	"auth_service/generated/auth/v1/authv1connect"
	"auth_service/handlers"
	"auth_service/internal/console"
	"auth_service/services"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	// Setup logger first
	logger := zap.L()

	// Load configuration using koanf
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", zap.Error(err))
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.Error("Invalid configuration", zap.Error(err))
	}

	// Print configuration for debugging
	cfg.Print()
	logger.Info("Starting Auth Service...")

	// Initialize database
	db, err := database.NewDatabase(&cfg.Database, logger.Sugar())
	if err != nil {
		logger.Error("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		logger.Error("Failed to run migrations", zap.Error(err))
	}

	logger.Info("Database connected and migrations completed")

	// Initialize DAOs
	userDAO := dao.NewUserDAO(db)

	// Initialize services
	passwordService := services.NewPasswordService()
	jwtService := services.NewJWTService(&cfg.JWT, db)

	// Create a simple logger for code service
	stdLogger := log.New(os.Stdout, "", log.LstdFlags)
	zLogger := getZerologLogger(stdLogger)
	codeService := services.NewCodeService(db, &cfg.SMTP, &cfg.SMS, zLogger)

	// Initialize Redis client for registration codes
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.GetRedisAddr(),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		logger.Error("Failed to connect to Redis", zap.Error(err))
	}
	regCodeService := services.NewRegistrationCodeService(redisClient, zLogger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(
		db,
		userDAO,
		passwordService,
		jwtService,
		codeService,
		regCodeService,
		stdLogger,
	)

	// Registration HTTP routes will be registered after router initialization

	// Initialize console module (integrated mode)
	consoleEnabled := os.Getenv("CONSOLE_ENABLED") != "false" // Default enabled
	var consoleModule *console.Console
	if consoleEnabled {
		consoleConfig := console.Config{
			JWTSecret: cfg.JWT.AccessSecret,
			Enabled:   true,
		}

		consoleModule, err = console.NewConsole(db.DB, consoleConfig)
		if err != nil {
			logger.Error("Warning: Failed to initialize console module", zap.Error(err))
			consoleModule = nil
		} else {
			logger.Info("Console module initialized successfully")
		}
	}

	// Setup HTTP server
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS
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

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Health(); err != nil {
			http.Error(w, "Database unhealthy", http.StatusServiceUnavailable)
			return
		}

		// Check console health if enabled
		if consoleModule != nil {
			if err := consoleModule.Health(); err != nil {
				http.Error(w, fmt.Sprintf("Console unhealthy: %v", err), http.StatusServiceUnavailable)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	// Connect-RPC handlers for auth service (with interceptors)
	connectOpts := []connect.HandlerOption{
		connect.WithInterceptors(
			connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
				return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
					start := time.Now()
					resp, err := next(ctx, req)
					duration := time.Since(start)
					if err != nil {
						logger.Error("ConnectRPC call failed",
							zap.String("procedure", req.Spec().Procedure),
							zap.Duration("duration", duration),
							zap.Error(err),
						)
					} else {
						logger.Info("ConnectRPC call completed",
							zap.String("procedure", req.Spec().Procedure),
							zap.Duration("duration", duration),
						)
					}
					return resp, err
				})
			}),
		),
	}
	authServicePath, authServiceHandler := authv1connect.NewAuthServiceHandler(authHandler, connectOpts...)
	router.Mount(authServicePath, authServiceHandler)

	// gRPC reflection for development/debugging
	reflector := grpcreflect.NewStaticReflector(
		authv1connect.AuthServiceName,
	)
	reflectionPath, reflectionHandler := grpcreflect.NewHandlerV1Alpha(reflector)
	router.Mount(reflectionPath, reflectionHandler)

	// Console routes (if enabled)
	if consoleModule != nil {
		logger.Info("Mounting console routes at /admin/*")
		consoleMux := http.NewServeMux()
		consoleModule.RegisterRoutes(consoleMux)
		router.Mount("/admin", consoleMux)
	}

	// Additional routes for testing
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		status := "Auth Service v0.4 - Running on port " + fmt.Sprintf("%d", cfg.Server.Port)
		if consoleModule != nil {
			status += " (Console enabled)"
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, status)
	})

	// Create HTTP server (h2c enables HTTP/2 cleartext for ConnectRPC)
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      h2c.NewHandler(router, &http2.Server{}),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	fmt.Println("Server starting on port", cfg.Server.Port)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := db.CleanupExpiredTokens(); err != nil {
					logger.Error("Failed to cleanup expired tokens", zap.Error(err))
				}
				if err := jwtService.CleanupExpiredBlacklist(); err != nil {
					logger.Error("Failed to cleanup expired blacklist", zap.Error(err))
				}
				if err := codeService.CleanupExpiredCodes(); err != nil {
					logger.Error("Failed to cleanup expired codes", zap.Error(err))
				}
			}
		}
	}()

	// Start server in a goroutine
	go func() {
		logger.Info("Server starting on port", zap.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", zap.Error(err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited")
}

func getZerologLogger(logger *log.Logger) zerolog.Logger {
	return zerolog.New(logger.Writer()).Level(zerolog.InfoLevel).With().Timestamp().Logger()
}

// SimpleLogger adapts standard logger to zerolog-like interface
type SimpleLogger struct {
	logger *log.Logger
}

func (l *SimpleLogger) Error() *SimpleLogEvent {
	return &SimpleLogEvent{logger: l.logger, level: "ERROR"}
}

func (l *SimpleLogger) Info() *SimpleLogEvent {
	return &SimpleLogEvent{logger: l.logger, level: "INFO"}
}

func (l *SimpleLogger) Debug() *SimpleLogEvent {
	return &SimpleLogEvent{logger: l.logger, level: "DEBUG"}
}

type SimpleLogEvent struct {
	logger *log.Logger
	level  string
	fields map[string]interface{}
}

func (e *SimpleLogEvent) Err(err error) *SimpleLogEvent {
	if e.fields == nil {
		e.fields = make(map[string]interface{})
	}
	e.fields["error"] = err
	return e
}

func (e *SimpleLogEvent) Str(key, val string) *SimpleLogEvent {
	if e.fields == nil {
		e.fields = make(map[string]interface{})
	}
	e.fields[key] = val
	return e
}

func (e *SimpleLogEvent) Msg(msg string) {
	logMsg := fmt.Sprintf("[%s] %s", e.level, msg)
	if len(e.fields) > 0 {
		logMsg += fmt.Sprintf(" %+v", e.fields)
	}
	e.logger.Println(logMsg)
}
