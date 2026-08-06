package logging

import (
	"context"
	"time"
)

// A Record is what a Logger asks its handler to write
type Record struct {
	PackageName string
	Time        time.Time
	Lvl         Lvl
	Message     string
	Ctx         context.Context
	// Fields carries the structured key/value pairs attached via FieldLogger.With and the *W log
	// methods. It is nil for records produced by the printf-style methods.
	//
	// Custom formatters installed through SetLogFormat or SetMessageFormat are handed the whole
	// Record and may render Fields however they like; if they ignore it, structured fields do not
	// appear in their output.
	Fields []Field
}
