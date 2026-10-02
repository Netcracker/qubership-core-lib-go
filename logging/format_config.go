package logging

import (
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

// Format selects how a log record is rendered.
type Format int

const (
	// FormatText is the historical bracketed text pattern. It is the default, so upgrading the
	// library never changes a service's output on its own.
	FormatText Format = iota
	// FormatJSON renders one JSON document per record.
	FormatJSON
)

const (
	// FormatPropertyName is the configloader property selecting the log format.
	FormatPropertyName = "logging.format"
	// FormatEnvName is the environment variable read during bootstrap, before configloader is
	// initialised.
	FormatEnvName = "LOGGING_FORMAT"
)

func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	default:
		return "text"
	}
}

// LogFormatFunc renders a record into the bytes written to the log output.
type LogFormatFunc = func(r *Record) []byte

// Bound once at package initialisation: taking DefaultFormat.format on every log call would
// allocate a fresh method value each time.
var (
	textFormatFunc LogFormatFunc = DefaultFormat.format
	jsonFormatFunc LogFormatFunc = JSONFormat.format
)

var (
	// activeFormat is the resolved Format, as an int32 so it can be swapped atomically while
	// other goroutines are logging.
	activeFormat atomic.Int32

	// globalLogFormat is a caller-supplied formatter installed via SetLogFormat. When non-nil it
	// wins over activeFormat.
	globalLogFormat atomic.Pointer[LogFormatFunc]

	// globalFormatExplicit records that the format was chosen deliberately -- through
	// SetOutputFormat, SetLogFormat or the HTTP endpoint -- rather than derived from
	// configuration. A configloader refresh must not silently undo such a choice.
	globalFormatExplicit atomic.Bool

	// globalOut is the default destination for every logger that has no writer of its own. A nil
	// value means os.Stdout, resolved at write time rather than captured here, because tests
	// (and the deadlock-guard test in particular) reassign os.Stdout after loggers are created.
	globalOut atomic.Pointer[io.Writer]
)

func init() {
	applyResolvedFormat()
}

// parseFormat maps a configured string to a Format. Reports false for anything unrecognised so
// callers can decide whether that is an error (the HTTP endpoint) or a silent fallback
// (configuration bootstrap).
func parseFormat(value string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return FormatJSON, true
	case "text":
		return FormatText, true
	default:
		return FormatText, false
	}
}

// resolveFormatFromConfig reads the format using the same two-phase lookup as the log level: the
// configloader property once configuration is up, and the raw environment variable before that.
//
// An unrecognised value falls back to text silently. This runs from GetLogger, so reporting the
// problem by logging it risks re-entering the registry during its own initialisation; and failing
// a service's startup over a typo in a log-format setting would be worse than defaulting.
func resolveFormatFromConfig() Format {
	var configured string
	if configloader.IsConfigLoaderInited() {
		configured = configloader.GetOrDefaultString(FormatPropertyName, "")
	} else if fromEnv, present := os.LookupEnv(FormatEnvName); present {
		configured = fromEnv
	}

	format, _ := parseFormat(configured)
	return format
}

// applyResolvedFormat re-reads the configured format. Called at package initialisation and from
// the configloader event subscription, so a refresh picks up a changed property -- unless the
// format was set explicitly, which always wins.
func applyResolvedFormat() {
	if globalFormatExplicit.Load() {
		return
	}
	activeFormat.Store(int32(resolveFormatFromConfig()))
}

func formatFuncFor(f Format) LogFormatFunc {
	if f == FormatJSON {
		return jsonFormatFunc
	}
	return textFormatFunc
}

// SetOutputFormat selects the log format programmatically. The choice is explicit and therefore
// survives any later configloader refresh.
//
// It is deliberately not named SetFormat: older revisions of this package's README documented a
// logging.SetFormat that never existed, and reusing the name would silently mislead anyone who
// copied that example.
func SetOutputFormat(f Format) {
	activeFormat.Store(int32(f))
	globalFormatExplicit.Store(true)
}

// GetOutputFormat reports the format currently in effect.
func GetOutputFormat() Format {
	return Format(activeFormat.Load())
}

// IsOutputFormatExplicit reports whether the active format was set deliberately (via
// SetOutputFormat, SetLogFormat or the HTTP endpoint) rather than derived from configuration.
// Useful when diagnosing why a configured format "will not stick".
func IsOutputFormatExplicit() bool {
	return globalFormatExplicit.Load()
}

// SetOutput sets the destination for every logger that does not have one of its own.
// Passing nil restores the default, os.Stdout.
func SetOutput(w io.Writer) {
	if w == nil {
		globalOut.Store(nil)
		return
	}
	globalOut.Store(&w)
}

// resolveGlobalWriter returns the process-wide log destination, defaulting to os.Stdout read at
// call time so that reassigning os.Stdout still takes effect.
func resolveGlobalWriter() io.Writer {
	if w := globalOut.Load(); w != nil {
		return *w
	}
	return os.Stdout
}
