package auth

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/generated/auth/v1/authv1connect"
	"github.com/all2prosperity/auth_service/handlers"
	"github.com/all2prosperity/auth_service/internal/console"
	"github.com/all2prosperity/auth_service/services"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AuthModule represents the auth service as a module
type AuthModule struct {
	config        *config.Config
	db            *database.DB
	authHandler   *handlers.AuthHandler
	consoleModule *console.Console
	logger        *log.Logger
	zapLogger     *zap.Logger
	redisClient   *redis.Client
	ownRedis      bool // whether we created the redis client
}

// AuthModuleConfig contains configuration for initializing the auth module
type AuthModuleConfig struct {
	// Database connection (required - choose one)
	DB *gorm.DB
	// Or SQL DB if you want to manage connection yourself
	SQLDB *sql.DB
	// Redis client (optional, will create one if not provided)
	Redis *redis.Client
	// Config (optional, will load from default if not provided)
	Config *config.Config
	// Logger (optional, will create default if not provided)
	Logger        *log.Logger
	ZapLogger     *zap.Logger
	ZerologLogger *zerolog.Logger
	// Console enabled (default: true)
	ConsoleEnabled bool
}

// NewAuthModule creates a new auth module instance
func NewAuthModule(cfg AuthModuleConfig) (*AuthModule, error) {
	var err error
	module := &AuthModule{}

	// Initialize logger
	if cfg.Logger != nil {
		module.logger = cfg.Logger
	} else {
		module.logger = log.Default()
	}

	if cfg.ZapLogger != nil {
		module.zapLogger = cfg.ZapLogger
	} else {
		module.zapLogger = zap.L()
	}

	// Load configuration
	if cfg.Config != nil {
		module.config = cfg.Config
	} else {
		module.config, err = config.LoadConfig()
		if err != nil {
			return nil, err
		}
	}

	// Initialize database
	if cfg.DB != nil {
		// Use provided GORM DB
		module.db = database.NewDatabaseFromGORM(cfg.DB)
	} else if cfg.SQLDB != nil {
		// Use provided SQL DB - need to wrap it
		module.db, err = database.NewDatabaseFromSQL(cfg.SQLDB, module.zapLogger.Sugar())
		if err != nil {
			return nil, err
		}
	} else {
		// Create new database connection
		module.db, err = database.NewDatabase(&module.config.Database, module.zapLogger.Sugar())
		if err != nil {
			return nil, err
		}
	}

	// Run migrations
	if err := module.db.AutoMigrate(); err != nil {
		return nil, err
	}

	// Initialize Redis
	if cfg.Redis != nil {
		module.redisClient = cfg.Redis
		module.ownRedis = false
	} else {
		module.redisClient = redis.NewClient(&redis.Options{
			Addr:     module.config.GetRedisAddr(),
			Password: module.config.Redis.Password,
			DB:       module.config.Redis.DB,
		})
		module.ownRedis = true
		// Test connection
		if err := module.redisClient.Ping(context.Background()).Err(); err != nil {
			module.logger.Printf("Warning: Failed to connect to Redis: %v", err)
		}
	}

	// Initialize services and handlers
	err = module.initializeServices()
	if err != nil {
		return nil, err
	}

	// Initialize console if enabled
	if cfg.ConsoleEnabled {
		consoleConfig := console.Config{
			JWTSecret: module.config.JWT.AccessSecret,
			Enabled:   true,
		}
		module.consoleModule, err = console.NewConsole(module.db.DB, consoleConfig)
		if err != nil {
			module.logger.Printf("Warning: Failed to initialize console module: %v", err)
			module.consoleModule = nil
		}
	}

	return module, nil
}

// initializeServices initializes all the services and handlers
func (m *AuthModule) initializeServices() error {
	// Initialize DAOs
	userDAO := dao.NewUserDAO(m.db)

	// Initialize services
	passwordService := services.NewPasswordService()
	jwtService := services.NewJWTService(&m.config.JWT, m.db)

	// Create zerolog logger for code service
	zLogger := getZerologLogger(m.logger)
	codeService := services.NewCodeService(m.db, &m.config.SMTP, &m.config.SMS, zLogger)
	regCodeService := services.NewRegistrationCodeService(m.redisClient, zLogger)

	// Initialize auth handler
	m.authHandler = handlers.NewAuthHandler(
		m.db,
		userDAO,
		passwordService,
		jwtService,
		codeService,
		regCodeService,
		m.logger,
	)

	return nil
}

// RegisterRoutes registers auth routes to the provided router
func (m *AuthModule) RegisterRoutes(router chi.Router) {
	// Connect-RPC handlers for auth service
	connectOpts := []connect.HandlerOption{
		connect.WithInterceptors(
			connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
				return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
					start := time.Now()
					resp, err := next(ctx, req)
					duration := time.Since(start)
					if err != nil {
						m.zapLogger.Error("ConnectRPC call failed",
							zap.String("procedure", req.Spec().Procedure),
							zap.Duration("duration", duration),
							zap.Error(err),
						)
					} else {
						m.zapLogger.Info("ConnectRPC call completed",
							zap.String("procedure", req.Spec().Procedure),
							zap.Duration("duration", duration),
						)
					}
					return resp, err
				})
			}),
		),
	}

	authServicePath, authServiceHandler := authv1connect.NewAuthServiceHandler(m.authHandler, connectOpts...)
	router.Mount(authServicePath, authServiceHandler)

	// gRPC reflection for development/debugging
	reflector := grpcreflect.NewStaticReflector(
		authv1connect.AuthServiceName,
	)
	reflectionPath, reflectionHandler := grpcreflect.NewHandlerV1Alpha(reflector)
	router.Mount(reflectionPath, reflectionHandler)
}

// RegisterConsoleRoutes registers console admin routes (if console is enabled)
func (m *AuthModule) RegisterConsoleRoutes(mux *http.ServeMux) {
	if m.consoleModule != nil {
		m.consoleModule.RegisterRoutes(mux)
	}
}

// Health checks the health of the auth module
func (m *AuthModule) Health() error {
	if err := m.db.Health(); err != nil {
		return err
	}
	if m.consoleModule != nil {
		return m.consoleModule.Health()
	}
	return nil
}

// Close closes the auth module and releases resources
func (m *AuthModule) Close() error {
	// Close redis connection if we created it
	if m.ownRedis && m.redisClient != nil {
		if err := m.redisClient.Close(); err != nil {
			m.logger.Printf("Error closing Redis connection: %v", err)
		}
	}

	// Close database connection
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// GetConfig returns the module configuration
func (m *AuthModule) GetConfig() *config.Config {
	return m.config
}

// GetHandler returns the auth handler (for advanced usage)
func (m *AuthModule) GetHandler() *handlers.AuthHandler {
	return m.authHandler
}

// GetDatabase returns the database instance (for advanced usage)
func (m *AuthModule) GetDatabase() *database.DB {
	return m.db
}

// StartCleanupRoutine starts a background goroutine for cleanup tasks
func (m *AuthModule) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.db.CleanupExpiredTokens(); err != nil {
					m.zapLogger.Error("Failed to cleanup expired tokens", zap.Error(err))
				}

				// Get JWT service for blacklist cleanup
				if m.authHandler != nil {
					// Note: This would require exposing JWT service or adding cleanup method to handler
					m.logger.Println("Cleanup cycle completed")
				}
			}
		}
	}()
}

func getZerologLogger(logger *log.Logger) zerolog.Logger {
	return zerolog.New(logger.Writer()).Level(zerolog.InfoLevel).With().Timestamp().Logger()
}
