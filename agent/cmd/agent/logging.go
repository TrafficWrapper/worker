package main

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

const (
	logLevelDebug int32 = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

var currentLogLevel atomic.Int32

func init() {
	currentLogLevel.Store(parseLogLevel(os.Getenv("LOG_LEVEL")))
}

func parseLogLevel(value string) int32 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return logLevelDebug
	case "warn", "warning":
		return logLevelWarn
	case "error":
		return logLevelError
	default:
		return logLevelInfo
	}
}

// logDebugf is for messages that repeat on every loop iteration; they are
// hidden unless LOG_LEVEL=debug.
func logDebugf(format string, args ...any) {
	if currentLogLevel.Load() <= logLevelDebug {
		log.Printf(format, args...)
	}
}
