// Package env reads configuration from the environment.
package env

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// String returns the trimmed value of name, or fallback when it is unset.
// A variable set to the empty string stays empty: that is how a deployment
// switches an optional upstream proxy off.
func String(name, fallback string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	return strings.TrimSpace(value)
}

// Int returns name as an integer, or fallback when unset or unparsable.
func Int(name string, fallback int) int {
	if value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return value
	}
	return fallback
}

// Seconds returns name, a number of seconds, as a duration.
func Seconds(name string, fallback float64) time.Duration {
	seconds := fallback
	if value, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil {
		seconds = value
	}
	return time.Duration(seconds * float64(time.Second))
}

// Bool is true for 1, true or yes.
func Bool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
