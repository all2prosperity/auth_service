package logger

import (
	"io"
	"log"
	"os"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Level represents logging levels
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

// Format represents logging formats
type Format int

const (
	JSONFormat Format = iota
	TextFormat
)

// Config holds logger configuration
type Config struct {
	Level  Level  `koanf:"level"`
	Format Format `koanf:"format"`
	Output string `koanf:"output"`
}

// Logger provides a unified interface for different logger implementations
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	WithFields(fields ...Field) Logger
}

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value interface{}
}

// String creates a string field
func String(key, val string) Field {
	return Field{Key: key, Value: val}
}

// Int creates an integer field
func Int(key string, val int) Field {
	return Field{Key: key, Value: val}
}

// Error creates an error field
func Err(key string, err error) Field {
	return Field{Key: key, Value: err}
}

// Duration creates a duration field
func Duration(key string, val interface{}) Field {
	return Field{Key: key, Value: val}
}

// Manager manages different logger implementations
type Manager struct {
	zapLogger     *zap.Logger
	zerologLogger zerolog.Logger
	stdLogger     *log.Logger
	config        Config
}

// NewManager creates a new logger manager with the specified configuration
func NewManager(config Config) (*Manager, error) {
	manager := &Manager{config: config}

	// Determine output writer
	var writer io.Writer = os.Stdout
	if config.Output != "" && config.Output != "stdout" {
		// For file output, we could add file support here
		// For now, default to stdout
		writer = os.Stdout
	}

	// Initialize Zap logger
	zapConfig := zap.NewProductionConfig()
	if config.Format == TextFormat {
		zapConfig = zap.NewDevelopmentConfig()
	}

	zapConfig.Level = zap.NewAtomicLevelAt(zapLevelFromConfig(config.Level))
	zapLogger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}
	manager.zapLogger = zapLogger

	// Initialize Zerolog logger
	zerologLevel := zerologLevelFromConfig(config.Level)
	var zerologLogger zerolog.Logger
	if config.Format == TextFormat {
		zerologLogger = zerolog.New(zerolog.ConsoleWriter{Out: writer}).Level(zerologLevel).With().Timestamp().Logger()
	} else {
		zerologLogger = zerolog.New(writer).Level(zerologLevel).With().Timestamp().Logger()
	}
	manager.zerologLogger = zerologLogger

	// Initialize standard logger
	manager.stdLogger = log.New(writer, "", log.LstdFlags)

	return manager, nil
}

// GetZapLogger returns the Zap logger instance
func (m *Manager) GetZapLogger() *zap.Logger {
	return m.zapLogger
}

// GetZapSugarLogger returns the Zap sugar logger instance
func (m *Manager) GetZapSugarLogger() *zap.SugaredLogger {
	return m.zapLogger.Sugar()
}

// GetZerologLogger returns the Zerolog logger instance
func (m *Manager) GetZerologLogger() zerolog.Logger {
	return m.zerologLogger
}

// GetStdLogger returns the standard logger instance
func (m *Manager) GetStdLogger() *log.Logger {
	return m.stdLogger
}

// GetUnifiedLogger returns a unified logger interface using Zap as the backend
func (m *Manager) GetUnifiedLogger() Logger {
	return &unifiedLogger{zap: m.zapLogger}
}

// Close closes all loggers and flushes any buffered output
func (m *Manager) Close() error {
	return m.zapLogger.Sync()
}

// unifiedLogger implements the Logger interface using Zap as the backend
type unifiedLogger struct {
	zap *zap.Logger
}

func (l *unifiedLogger) Debug(msg string, fields ...Field) {
	l.zap.Debug(msg, l.convertFields(fields)...)
}

func (l *unifiedLogger) Info(msg string, fields ...Field) {
	l.zap.Info(msg, l.convertFields(fields)...)
}

func (l *unifiedLogger) Warn(msg string, fields ...Field) {
	l.zap.Warn(msg, l.convertFields(fields)...)
}

func (l *unifiedLogger) Error(msg string, fields ...Field) {
	l.zap.Error(msg, l.convertFields(fields)...)
}

func (l *unifiedLogger) WithFields(fields ...Field) Logger {
	return &unifiedLogger{zap: l.zap.With(l.convertFields(fields)...)}
}

func (l *unifiedLogger) convertFields(fields []Field) []zap.Field {
	zapFields := make([]zap.Field, len(fields))
	for i, field := range fields {
		switch v := field.Value.(type) {
		case string:
			zapFields[i] = zap.String(field.Key, v)
		case int:
			zapFields[i] = zap.Int(field.Key, v)
		case error:
			zapFields[i] = zap.Error(v)
		default:
			zapFields[i] = zap.Any(field.Key, v)
		}
	}
	return zapFields
}

// Helper functions to convert config levels to specific logger levels
func zapLevelFromConfig(level Level) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func zerologLevelFromConfig(level Level) zerolog.Level {
	switch level {
	case DebugLevel:
		return zerolog.DebugLevel
	case InfoLevel:
		return zerolog.InfoLevel
	case WarnLevel:
		return zerolog.WarnLevel
	case ErrorLevel:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// ParseLevel parses a string level to Level type
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	default:
		return InfoLevel
	}
}

// ParseFormat parses a string format to Format type
func ParseFormat(s string) Format {
	switch s {
	case "json":
		return JSONFormat
	case "text", "console":
		return TextFormat
	default:
		return JSONFormat
	}
}
