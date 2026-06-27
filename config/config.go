package config

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/all2prosperity/auth_service/internal/logger"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
)

// Config holds all configuration for the application
type Config struct {
	AppEnv   string         `koanf:"app_env"` // development | staging | production
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	JWT      JWTConfig      `koanf:"jwt"`
	SMTP     SMTPConfig     `koanf:"smtp"`
	SMS      SMSConfig      `koanf:"sms"`
	OAuth    OAuthConfig    `koanf:"oauth"`
	Redis    RedisConfig    `koanf:"redis"`
	Logging  LoggingConfig  `koanf:"logging"`
	Features FeatureConfig  `koanf:"features"`
	Security SecurityConfig `koanf:"security"`
}

type ServerConfig struct {
	Port         int           `koanf:"port"`
	Host         string        `koanf:"host"`
	ReadTimeout  time.Duration `koanf:"read_timeout"`
	WriteTimeout time.Duration `koanf:"write_timeout"`
	IdleTimeout  time.Duration `koanf:"idle_timeout"`
}

type DatabaseConfig struct {
	Host            string        `koanf:"host"`
	Port            int           `koanf:"port"`
	User            string        `koanf:"user"`
	Password        string        `koanf:"password"`
	DBName          string        `koanf:"db_name"`
	SSLMode         string        `koanf:"ssl_mode"`
	MaxOpenConns    int           `koanf:"max_open_conns"`
	MaxIdleConns    int           `koanf:"max_idle_conns"`
	ConnMaxLifetime time.Duration `koanf:"conn_max_lifetime"`
}

type JWTConfig struct {
	AccessSecret    string        `koanf:"access_secret"`
	RefreshSecret   string        `koanf:"refresh_secret"`
	AccessTokenTTL  time.Duration `koanf:"access_token_ttl"`
	RefreshTokenTTL time.Duration `koanf:"refresh_token_ttl"`
	Issuer          string        `koanf:"issuer"`
}

type SMTPConfig struct {
	Host      string `koanf:"host"`
	Port      int    `koanf:"port"`
	Username  string `koanf:"username"`
	Password  string `koanf:"password"`
	FromEmail string `koanf:"from_email"`
	FromName  string `koanf:"from_name"`
	TLS       bool   `koanf:"tls"`
}

type SMSConfig struct {
	Provider        string `koanf:"provider"` // twilio, aliyun
	TwilioSID       string `koanf:"twilio_sid"`
	TwilioToken     string `koanf:"twilio_token"`
	TwilioFrom      string `koanf:"twilio_from"`
	AliyunAccessKey string `koanf:"aliyun_access_key"`
	AliyunSecretKey string `koanf:"aliyun_secret_key"`
	AliyunSignName  string `koanf:"aliyun_sign_name"`
	AliyunTemplate  string `koanf:"aliyun_template"`
}

type OAuthConfig struct {
	Google  GoogleOAuthConfig `koanf:"google"`
	GitHub  GitHubOAuthConfig `koanf:"github"`
	Apple   AppleOAuthConfig  `koanf:"apple"`
	WeChat  WeChatOAuthConfig `koanf:"wechat"`
	BaseURL string            `koanf:"base_url"`
}

type GoogleOAuthConfig struct {
	ClientID     string `koanf:"client_id"`
	ClientSecret string `koanf:"client_secret"`
	RedirectURL  string `koanf:"redirect_url"`
}

type GitHubOAuthConfig struct {
	ClientID     string `koanf:"client_id"`
	ClientSecret string `koanf:"client_secret"`
	RedirectURL  string `koanf:"redirect_url"`
}

type AppleOAuthConfig struct {
	ClientID     string `koanf:"client_id"`
	ClientSecret string `koanf:"client_secret"`
	RedirectURL  string `koanf:"redirect_url"`
}

type WeChatOAuthConfig struct {
	AppID       string `koanf:"app_id"`
	AppSecret   string `koanf:"app_secret"`
	RedirectURL string `koanf:"redirect_url"`
}

type RedisConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	Password string `koanf:"password"`
	DB       int    `koanf:"db"`
}

type LoggingConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
	Output string `koanf:"output"`
}

// ToLoggerConfig converts LoggingConfig to logger.Config
func (c *LoggingConfig) ToLoggerConfig() logger.Config {
	return logger.Config{
		Level:  logger.ParseLevel(c.Level),
		Format: logger.ParseFormat(c.Format),
		Output: c.Output,
	}
}

type FeatureConfig struct {
	EnableConsole     bool `koanf:"enable_console"`
	EnableMetrics     bool `koanf:"enable_metrics"`
	EnableCORS        bool `koanf:"enable_cors"`
	EnableHealthCheck bool `koanf:"enable_health_check"`
}

// SecurityConfig holds security-related tunables (brute-force protection,
// verification-code limits, CORS whitelist, and the gated test bypass code).
type SecurityConfig struct {
	// TestBypassCode is a verification code that is accepted in non-production
	// environments only, and only when EnableTestBypass is true.
	TestBypassCode   string `koanf:"test_bypass_code"`
	EnableTestBypass bool   `koanf:"enable_test_bypass"`

	// CodeHMACSecret keys the HMAC used to hash verification codes before
	// storage. Falls back to the JWT access secret when empty.
	CodeHMACSecret string `koanf:"code_hmac_secret"`

	// Login brute-force protection.
	LoginMaxAttempts  int           `koanf:"login_max_attempts"`
	LoginLockDuration time.Duration `koanf:"login_lock_duration"`

	// CodeMaxAttempts caps failed verification-code attempts before the code
	// is invalidated.
	CodeMaxAttempts int `koanf:"code_max_attempts"`

	// AllowedOrigins is the CORS whitelist. Production must not use "*".
	AllowedOrigins []string `koanf:"allowed_origins"`

	// Global per-IP rate limiting.
	IPRateLimit  int           `koanf:"ip_rate_limit"`
	IPRateWindow time.Duration `koanf:"ip_rate_window"`
}

var (
	k         = koanf.New(".")
	appConfig *Config
	once      sync.Once
	configErr error
)

// LoadConfig loads configuration from multiple sources
func LoadConfig(configFiles ...string) (*Config, error) {
	// Set default configuration files
	defaultFiles := []string{
		"configs/local.yaml",
		"configs/auth.yaml",
		"config.yaml",
	}

	if len(configFiles) > 0 {
		defaultFiles = configFiles
	}

	// Load configuration from files (in order, later files override earlier ones)
	for _, configFile := range defaultFiles {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			// Don't fail if file doesn't exist, just log a warning
			if zap.L() != nil {
				zap.L().Debug("Config file not found, skipping", zap.String("file", configFile))
			}
		} else {
			zap.L().Info("Loaded configuration from file", zap.String("file", configFile))
			break
		}
	}

	// Load environment variables with prefix mapping
	envProvider := env.Provider("", ".", func(s string) string {
		// Convert environment variables to nested structure
		return strings.Replace(
			strings.Replace(
				strings.ToLower(s), "_", ".", -1),
			"..", ".", -1)
	})

	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// Set default values
	setDefaults(k)

	// Unmarshal configuration
	var config Config
	if err := k.Unmarshal("", &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	appConfig = &config
	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(k *koanf.Koanf) {
	defaults := map[string]interface{}{
		// App environment
		"app_env": "development",

		// Server defaults
		"server.port":          8080,
		"server.host":          "localhost",
		"server.read_timeout":  "10s",
		"server.write_timeout": "10s",
		"server.idle_timeout":  "120s",

		// Database defaults
		"database.host":              "localhost",
		"database.port":              5432,
		"database.user":              "postgres",
		"database.password":          "",
		"database.db_name":           "github.com/all2prosperity/auth_service",
		"database.ssl_mode":          "disable",
		"database.max_open_conns":    25,
		"database.max_idle_conns":    5,
		"database.conn_max_lifetime": "5m",

		// JWT defaults
		"jwt.access_secret":     "change-me-access-secret",
		"jwt.refresh_secret":    "change-me-refresh-secret",
		"jwt.access_token_ttl":  "15m",
		"jwt.refresh_token_ttl": "168h",
		"jwt.issuer":            "auth-service",

		// SMTP defaults
		"smtp.host":       "smtp.gmail.com",
		"smtp.port":       587,
		"smtp.username":   "",
		"smtp.password":   "",
		"smtp.from_email": "noreply@example.com",
		"smtp.from_name":  "Auth Service",
		"smtp.tls":        true,

		// SMS defaults
		"sms.provider":          "twilio",
		"sms.twilio_sid":        "",
		"sms.twilio_token":      "",
		"sms.twilio_from":       "",
		"sms.aliyun_access_key": "",
		"sms.aliyun_secret_key": "",
		"sms.aliyun_sign_name":  "",
		"sms.aliyun_template":   "",

		// OAuth defaults
		"oauth.base_url":             "http://localhost:8080",
		"oauth.google.client_id":     "",
		"oauth.google.client_secret": "",
		"oauth.google.redirect_url":  "",
		"oauth.github.client_id":     "",
		"oauth.github.client_secret": "",
		"oauth.github.redirect_url":  "",
		"oauth.apple.client_id":      "",
		"oauth.apple.client_secret":  "",
		"oauth.apple.redirect_url":   "",
		"oauth.wechat.app_id":        "",
		"oauth.wechat.app_secret":    "",
		"oauth.wechat.redirect_url":  "",

		// Redis defaults
		"redis.host":     "localhost",
		"redis.port":     6379,
		"redis.password": "",
		"redis.db":       0,

		// Logging defaults
		"logging.level":  "info",
		"logging.format": "json",
		"logging.output": "stdout",

		// Feature defaults
		"features.enable_console":      true,
		"features.enable_metrics":      true,
		"features.enable_cors":         true,
		"features.enable_health_check": true,

		// Security defaults
		"security.test_bypass_code":    "",
		"security.enable_test_bypass":  false,
		"security.code_hmac_secret":    "",
		"security.login_max_attempts":  5,
		"security.login_lock_duration": "15m",
		"security.code_max_attempts":   5,
		"security.allowed_origins":     []string{"*"},
		"security.ip_rate_limit":       100,
		"security.ip_rate_window":      "1m",
	}

	for key, value := range defaults {
		if !k.Exists(key) {
			k.Set(key, value)
		}
	}
}

// GetConfig returns the application configuration
func GetConfig() *Config {
	once.Do(func() {
		var config *Config
		config, configErr = LoadConfig()
		if configErr != nil {
			if zap.L() != nil {
				zap.L().Fatal("Failed to load configuration", zap.Error(configErr))
			}
		}
		appConfig = config
	})
	return appConfig
}

// GetDSN returns the database connection string
func (c *Config) GetDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.User, c.Database.Password, c.Database.Host, c.Database.Port, c.Database.DBName, c.Database.SSLMode)
}

// GetRedisAddr returns the Redis connection address
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}

// IsProduction reports whether the service is running in a production environment.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.AppEnv, "production") || strings.EqualFold(c.AppEnv, "prod")
}

// CodeHMACKey returns the key used to HMAC verification codes before storage.
// Falls back to the JWT access secret when no dedicated secret is configured.
func (c *Config) CodeHMACKey() string {
	if c.Security.CodeHMACSecret != "" {
		return c.Security.CodeHMACSecret
	}
	return c.JWT.AccessSecret
}

// defaultJWTSecrets are the placeholder secrets shipped in setDefaults; they must
// never be used in production.
var defaultJWTSecrets = map[string]bool{
	"change-me-access-secret":  true,
	"change-me-refresh-secret": true,
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Database.Port == 0 {
		return fmt.Errorf("database port is required")
	}
	if c.Database.User == "" {
		return fmt.Errorf("database user is required")
	}
	if c.Database.DBName == "" {
		return fmt.Errorf("database name is required")
	}
	if c.Server.Port == 0 {
		return fmt.Errorf("server port is required")
	}
	if c.JWT.AccessSecret == "" {
		return fmt.Errorf("JWT access secret is required")
	}
	if c.JWT.RefreshSecret == "" {
		return fmt.Errorf("JWT refresh secret is required")
	}

	if c.IsProduction() {
		// Reject weak/default JWT secrets in production.
		for _, s := range []string{c.JWT.AccessSecret, c.JWT.RefreshSecret} {
			if defaultJWTSecrets[s] {
				return fmt.Errorf("default JWT secret detected in production; set a strong jwt.access_secret/jwt.refresh_secret")
			}
			if len(s) < 32 {
				return fmt.Errorf("JWT secret must be at least 32 characters in production")
			}
		}
		// CORS must be locked down in production.
		if len(c.Security.AllowedOrigins) == 0 {
			return fmt.Errorf("security.allowed_origins must be set in production")
		}
		for _, o := range c.Security.AllowedOrigins {
			if o == "*" {
				return fmt.Errorf("security.allowed_origins must not contain \"*\" in production")
			}
		}
		// The test bypass code must never be active in production.
		if c.Security.EnableTestBypass {
			return fmt.Errorf("security.enable_test_bypass must be false in production")
		}
	} else {
		// Non-production: warn loudly but do not block local development.
		for _, s := range []string{c.JWT.AccessSecret, c.JWT.RefreshSecret} {
			if defaultJWTSecrets[s] || len(s) < 32 {
				if zap.L() != nil {
					zap.L().Warn("Weak or default JWT secret in use; do NOT use this configuration in production")
				}
				break
			}
		}
	}

	return nil
}

// Print prints the current configuration (for debugging)
func (c *Config) Print() {
	if zap.L() != nil {
		zap.L().Info("Current configuration",
			zap.String("server.host", c.Server.Host),
			zap.Int("server.port", c.Server.Port),
			zap.String("database.host", c.Database.Host),
			zap.Int("database.port", c.Database.Port),
			zap.String("database.db_name", c.Database.DBName),
			zap.String("jwt.issuer", c.JWT.Issuer),
			zap.Bool("features.enable_console", c.Features.EnableConsole),
			zap.Bool("features.enable_metrics", c.Features.EnableMetrics),
		)
	}
}
