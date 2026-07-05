package logging

import (
	"fmt"
	"strings"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	// LogLevelDebug is for debug messages
	LogLevelDebug LogLevel = "debug"
	// LogLevelInfo is for informational messages
	LogLevelInfo LogLevel = "info"
	// LogLevelWarn is for warning messages
	LogLevelWarn LogLevel = "warn"
	// LogLevelError is for error messages
	LogLevelError LogLevel = "error"
	// LogLevelPanic is for panic messages
	LogLevelPanic LogLevel = "panic"
)

var (
	// App is the global application logger
	App *AppLogger
	// Access is the global access logger
	Access AccessLogger
)

func init() {
	// Initialize default loggers that write to io.Discard
	var err error

	// Create no-op loggers by default (rotation params don't matter for empty path)
	App, err = NewAppLogger("", LogLevelInfo, 1000000, 45*time.Second)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize default app logger: %v", err))
	}

	Access, err = NewAccessLogger("", 1000000, 45*time.Second)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize default access logger: %v", err))
	}
}

// Initialize sets up the global loggers
func Initialize(accessLogPath, appLogPath string, level LogLevel, maxSize int64, verifyInterval time.Duration) error {
	var err error

	// Set default level if not specified
	if level == "" {
		level = LogLevelInfo
	}

	// Initialize access logger
	newAccess, err := NewAccessLogger(accessLogPath, maxSize, verifyInterval)
	if err != nil {
		return fmt.Errorf("failed to initialize access logger: %w", err)
	}

	// Initialize application logger
	newApp, err := NewAppLogger(appLogPath, level, maxSize, verifyInterval)
	if err != nil {
		return fmt.Errorf("failed to initialize app logger: %w", err)
	}

	// Close old loggers if they exist
	if Access != nil {
		_ = Access.Close()
	}
	if App != nil {
		_ = App.Close()
	}

	// Update global loggers
	Access = newAccess
	App = newApp

	return nil
}

// MustInitialize initializes logging and panics on error
func MustInitialize(accessLogPath, appLogPath string, level LogLevel, maxSize int64, verifyInterval time.Duration) {
	if err := Initialize(accessLogPath, appLogPath, level, maxSize, verifyInterval); err != nil {
		panic(fmt.Sprintf("failed to initialize logging: %v", err))
	}
}

// Shutdown closes all loggers and stops background rotation
func Shutdown() {
	if Access != nil {
		_ = Access.Close()
	}
	if App != nil {
		_ = App.Close()
	}
}

// formatValue formats a value for logfmt, quoting if necessary
func formatValue(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	// Neutralize control characters so a crafted username or path cannot forge
	// or split access-log lines (consistent with the app logger's handling).
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	// Quote if contains space, equals, or quotes
	if strings.ContainsAny(s, " =\"") {
		// Escape existing quotes
		s = strings.ReplaceAll(s, "\"", "\\\"")
		return fmt.Sprintf("\"%s\"", s)
	}
	return s
}
