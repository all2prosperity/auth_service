package auth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/dao"
	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/internal/console"
	"github.com/all2prosperity/auth_service/internal/logger"
	"github.com/all2prosperity/auth_service/services"
	"github.com/all2prosperity/auth_service/transport/rest"

	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// UserRegistrationInfo contains user information passed to registration callbacks
// This is an alias to the core package type for public API consistency
type UserRegistrationInfo = core.UserRegistrationInfo

// RegistrationHook is a callback function called after successful user registration
// This is an alias to the core package type for public API consistency
type RegistrationHook = core.RegistrationHook

// AuthHooks contains all available hooks for the auth module
type AuthHooks struct {
	// OnRegistered is called after successful user registration
	OnRegistered RegistrationHook
}

// AuthModule represents the auth service as a module
type AuthModule struct {
	config        *config.Config
	db            *database.DB
	authCore      *core.AuthCore
	consoleModule *console.Console
	loggerManager *logger.Manager
	redisClient   *redis.Client
	ownRedis      bool // whether we created the redis client
	hooks         *AuthHooks
	jwtService    *services.JWTService
	blacklist     *services.TokenBlacklist
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
	// Logger manager (optional, will create default if not provided)
	LoggerManager *logger.Manager
	// Legacy logger support (deprecated, use LoggerManager instead)
	Logger    *log.Logger
	ZapLogger *zap.Logger
	// Console enabled (default: true)
	ConsoleEnabled bool
	// Hooks for various auth events (optional)
	Hooks *AuthHooks
}

// NewAuthModule creates a new auth module instance
func NewAuthModule(cfg AuthModuleConfig) (*AuthModule, error) {
	var err error
	module := &AuthModule{}

	// Load configuration first
	if cfg.Config != nil {
		module.config = cfg.Config
	} else {
		module.config, err = config.LoadConfig()
		if err != nil {
			return nil, err
		}
	}

	// Initialize logger manager
	if cfg.LoggerManager != nil {
		module.loggerManager = cfg.LoggerManager
	} else {
		// Create logger manager from config
		loggerConfig := module.config.Logging.ToLoggerConfig()
		module.loggerManager, err = logger.NewManager(loggerConfig)
		if err != nil {
			// Fallback to default logger if config parsing fails
			defaultConfig := logger.Config{
				Level:  logger.InfoLevel,
				Format: logger.JSONFormat,
				Output: "stdout",
			}
			module.loggerManager, err = logger.NewManager(defaultConfig)
			if err != nil {
				return nil, err
			}
		}
	}

	// Get unified logger for module usage
	moduleLogger := module.loggerManager.GetUnifiedLogger()
	moduleLogger.Info("Initializing AuthModule")

	// Initialize database
	if cfg.DB != nil {
		// Use provided GORM DB
		module.db = database.NewDatabaseFromGORM(cfg.DB)
	} else if cfg.SQLDB != nil {
		// Use provided SQL DB - need to wrap it
		module.db, err = database.NewDatabaseFromSQL(cfg.SQLDB, module.loggerManager.GetZapSugarLogger())
		if err != nil {
			return nil, err
		}
	} else {
		// Create new database connection
		module.db, err = database.NewDatabase(&module.config.Database, module.loggerManager.GetZapSugarLogger())
		if err != nil {
			return nil, err
		}
	}

	// Run migrations
	if err := module.db.AutoMigrate(); err != nil {
		return nil, err
	}
	moduleLogger.Info("Database initialized and migrations completed")

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
			moduleLogger.Warn("Failed to connect to Redis", logger.Err("error", err))
		} else {
			moduleLogger.Info("Redis connection established")
		}
	}

	// Set up hooks
	if cfg.Hooks != nil {
		module.hooks = cfg.Hooks
	} else {
		module.hooks = &AuthHooks{}
	}

	// Initialize services and handlers
	err = module.initializeServices()
	if err != nil {
		return nil, err
	}
	moduleLogger.Info("Services initialized successfully")

	// Initialize console if enabled
	if cfg.ConsoleEnabled {
		consoleConfig := console.Config{
			JWTSecret:    module.config.JWT.AccessSecret,
			Enabled:      true,
			TokenRevoker: module.blacklist,
		}
		module.consoleModule, err = console.NewConsole(module.db.DB, consoleConfig)
		if err != nil {
			moduleLogger.Warn("Failed to initialize console module", logger.Err("error", err))
			module.consoleModule = nil
		} else {
			moduleLogger.Info("Console module initialized successfully")
		}
	}

	moduleLogger.Info("AuthModule initialization completed successfully")
	return module, nil
}

// initializeServices initializes all the services and handlers
func (m *AuthModule) initializeServices() error {
	// Initialize DAOs
	userDAO := dao.NewUserDAO(m.db)

	// Initialize services
	passwordService := services.NewPasswordService()
	jwtService := services.NewJWTService(&m.config.JWT)

	// Token blacklist for server-side revocation (logout, refresh rotation,
	// admin "revoke all sessions"). Retain epoch counters at least as long as
	// the refresh-token lifetime.
	m.blacklist = services.NewTokenBlacklist(m.redisClient, m.config.JWT.RefreshTokenTTL)
	jwtService.SetBlacklist(m.blacklist)
	m.jwtService = jwtService

	loginAttemptDAO := dao.NewLoginAttemptDAO(m.db)

	isProd := m.config.IsProduction()

	// Use zerolog logger for services that require it
	zerologLogger := m.loggerManager.GetZerologLogger()
	codeService, err := services.NewCodeService(m.db, &m.config.SMTP, &m.config.SMS, &m.config.Security, m.config.CodeHMACKey(), isProd, zerologLogger)
	if err != nil {
		return fmt.Errorf("failed to create code service: %w", err)
	}
	regCodeService, err := services.NewRegistrationCodeService(m.redisClient, &m.config.SMS, &m.config.Security, isProd, zerologLogger)
	if err != nil {
		return fmt.Errorf("failed to create registration code service: %w", err)
	}

	// Initialize the transport-agnostic auth core
	m.authCore = core.NewAuthCore(
		m.db,
		userDAO,
		loginAttemptDAO,
		passwordService,
		jwtService,
		codeService,
		regCodeService,
		m.blacklist,
		&m.config.Security,
		m.loggerManager.GetStdLogger(),
	)

	// Set the registration hook in the core
	m.authCore.SetRegistrationHook(m.hooks.OnRegistered)

	return nil
}

// RegisterRoutes registers the auth REST API onto the provided router.
func (m *AuthModule) RegisterRoutes(router chi.Router) {
	rest.RegisterRoutes(router, m.authCore, m.jwtService)
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
	var errors []error

	// Close redis connection if we created it
	if m.ownRedis && m.redisClient != nil {
		if err := m.redisClient.Close(); err != nil {
			m.loggerManager.GetUnifiedLogger().Error("Error closing Redis connection", logger.Err("error", err))
			errors = append(errors, err)
		}
	}

	// Close database connection
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	// Close logger manager
	if m.loggerManager != nil {
		if err := m.loggerManager.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing auth module: %v", errors)
	}
	return nil
}

// GetConfig returns the module configuration
func (m *AuthModule) GetConfig() *config.Config {
	return m.config
}

// GetCore returns the transport-agnostic auth core (for advanced usage).
func (m *AuthModule) GetCore() *core.AuthCore {
	return m.authCore
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

		moduleLogger := m.loggerManager.GetUnifiedLogger()
		moduleLogger.Info("Starting cleanup routine")

		for {
			select {
			case <-ticker.C:
				if err := m.db.CleanupExpiredTokens(); err != nil {
					moduleLogger.Error("Failed to cleanup expired tokens", logger.Err("error", err))
				} else {
					moduleLogger.Debug("Cleanup cycle completed successfully")
				}
			}
		}
	}()
}

// GetLoggerManager returns the logger manager (for advanced usage)
func (m *AuthModule) GetLoggerManager() *logger.Manager {
	return m.loggerManager
}

// GetLogger returns a unified logger interface
func (m *AuthModule) GetLogger() logger.Logger {
	return m.loggerManager.GetUnifiedLogger()
}

// GetZapLogger returns the Zap logger (for legacy compatibility)
func (m *AuthModule) GetZapLogger() *zap.Logger {
	return m.loggerManager.GetZapLogger()
}

// GetStdLogger returns the standard logger (for legacy compatibility)
func (m *AuthModule) GetStdLogger() *log.Logger {
	return m.loggerManager.GetStdLogger()
}

// SetRegistrationHook sets the registration callback hook
func (m *AuthModule) SetRegistrationHook(hook RegistrationHook) {
	if m.hooks == nil {
		m.hooks = &AuthHooks{}
	}
	m.hooks.OnRegistered = hook
	if m.authCore != nil {
		m.authCore.SetRegistrationHook(hook)
	}
}

// GetRegistrationHook returns the current registration hook
func (m *AuthModule) GetRegistrationHook() RegistrationHook {
	if m.hooks == nil {
		return nil
	}
	return m.hooks.OnRegistered
}

// SetHooks sets all hooks at once
func (m *AuthModule) SetHooks(hooks *AuthHooks) {
	m.hooks = hooks
	if m.authCore != nil && hooks != nil {
		m.authCore.SetRegistrationHook(hooks.OnRegistered)
	}
}
