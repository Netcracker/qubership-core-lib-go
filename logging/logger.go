package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	lock "github.com/viney-shih/go-lock"
)

// List of predefined log Levels
const (
	LvlCrit Lvl = iota
	LvlError
	LvlWarn
	LvlInfo
	LvlDebug
)

// Lvl is a type for predefined log levels.
type Lvl int

type LogLevels map[string]string

type logger struct {
	maxLvl Lvl
	name   string
	// logFormat is a per-logger formatter override. Atomic because SetLogFormat may be called
	// while other goroutines are logging.
	logFormat atomic.Pointer[LogFormatFunc]
	// out is a per-logger output override; nil falls through to the global writer.
	out atomic.Pointer[io.Writer]
	// mutex for sync log
	mu              *lock.ChanMutex
	rwLockForMaxLvl sync.RWMutex

	// base is set on loggers produced by With and points at the registered logger they derive
	// from. A derived logger is a view, not a copy: level, formatter, writer and write mutex all
	// live on the base, so a configuration change or a level refresh applies to it too.
	base *logger
	// fields are the structured key/value pairs accumulated by With. Immutable once constructed.
	fields []Field
}

var (
	registeredLoggers sync.Map
	once              sync.Once
	defaultMaxLevel   = LvlInfo
	envNameRegexp     = regexp.MustCompile(`[^a-zA-Z0-9_]+`)
)

// A Logger writes key/value pairs to a Handler
type Logger interface {
	GetLevel() Lvl

	// SetLevel updates the logger to set specific max level to write for
	SetLevel(maxLvl Lvl)
	SetLogFormat(logFormat func(r *Record) []byte)
	SetMessageFormat(fn messageFmt)

	// Log a Message at the given level
	Debug(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	DebugC(ctx context.Context, format string, args ...interface{})

	Info(format string, args ...interface{})
	Infof(format string, args ...interface{})
	InfoC(ctx context.Context, format string, args ...interface{})

	Warn(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	WarnC(ctx context.Context, format string, args ...interface{})

	Error(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	ErrorC(ctx context.Context, format string, args ...interface{})

	Panic(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	PanicC(ctx context.Context, format string, args ...interface{})
}

// FieldLogger extends Logger with structured key/value fields, in the style of log/slog.
//
// It is a separate interface rather than extra methods on Logger because Logger is exported and
// implemented by downstream mocks and test doubles; adding a method to it would break every one of
// them at compile time. Logger is therefore frozen, and all new capability lands here.
//
// Obtain one with GetFieldLogger, or adapt an existing Logger with Fields.
//
//	log := logging.GetFieldLogger("orders")
//	log.InfoWC(ctx, "order placed", "order_id", id, "customer", name)
//
//	scoped := log.With("component", "checkout")
//	scoped.WarnW("retrying", "attempt", 2)
//
// Unlike the printf-style methods, msg is a literal: it is never run through fmt.Sprintf, so a
// message may contain '%' freely. Remaining arguments are alternating keys and values; a malformed
// list is logged under the !BADKEY key rather than panicking or being dropped.
//
// FieldLogger is NOT frozen -- later minor versions may add methods. Downstream fakes should embed
// logging.FieldLogger rather than reimplementing it.
type FieldLogger interface {
	Logger

	// With returns a logger that adds the given key/value pairs to every record it writes.
	// The receiver is unchanged. Level, formatter and output stay shared with the parent, so a
	// level refresh or an HTTP level change applies to derived loggers too.
	With(args ...any) FieldLogger

	// SetOutput overrides the destination for this logger.
	SetOutput(w io.Writer)

	DebugW(msg string, args ...any)
	InfoW(msg string, args ...any)
	WarnW(msg string, args ...any)
	ErrorW(msg string, args ...any)
	PanicW(msg string, args ...any)

	DebugWC(ctx context.Context, msg string, args ...any)
	InfoWC(ctx context.Context, msg string, args ...any)
	WarnWC(ctx context.Context, msg string, args ...any)
	ErrorWC(ctx context.Context, msg string, args ...any)
	PanicWC(ctx context.Context, msg string, args ...any)
}

// Compile-time guarantee that the concrete logger satisfies both interfaces.
var (
	_ Logger      = (*logger)(nil)
	_ FieldLogger = (*logger)(nil)
)

func watch() {
	_, err := configloader.Subscribe(func(event configloader.Event) error {
		if event.Type == configloader.InitedEventT || event.Type == configloader.RefreshedEventT {
			// Re-read the log format from the same event that refreshes levels, so both follow
			// configuration without a second subscription.
			applyResolvedFormat()
			rootLevel := defineRootLvl(defaultMaxLevel.String())
			registeredLoggers.Range(func(key, value interface{}) bool {
				logLevel := definePackageLvl(value.(*logger).name)
				if logLevel == "" {
					logLevel = rootLevel
				}
				lvl, _ := lvlFromString(logLevel)
				if currLogger, ok := registeredLoggers.Load(key); ok {
					currLogger.(*logger).SetLevel(lvl)
					registeredLoggers.Store(key, currLogger)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func readLvlFromConfig(pkg string) string {
	if configloader.IsConfigLoaderInited() {
		packageLvl := definePackageLvl(pkg)
		if packageLvl != "" {
			return packageLvl
		}
		defaultLvl := defineRootLvl(defaultMaxLevel.String())
		return defaultLvl
	} else {
		pkgEnvSuffix := envNameRegexp.ReplaceAllString(strings.ToUpper(pkg), "_")
		envHierarchy := [4]string{
			"LOGGING_LEVEL_" + pkgEnvSuffix,
			"LOG_LEVEL_PACKAGE_" + pkgEnvSuffix,
			"LOGGING_LEVEL_ROOT",
			"LOG_LEVEL",
		}
		for _, env := range envHierarchy {
			if res, isExist := os.LookupEnv(env); isExist {
				return res
			}
		}
		return defaultMaxLevel.String()
	}
}

func definePackageLvl(pkg string) string {
	logPkgString := fmt.Sprintf("logging.level.%s", pkg)
	level := configloader.GetOrDefaultString(logPkgString, "")
	if level == "" {
		logPkgString := fmt.Sprintf("log.level.package.%s", pkg)
		level = configloader.GetOrDefaultString(logPkgString, "")
	}
	return level
}

func defineRootLvl(defaultValue string) string {
	logRootString := "logging.level.root"
	level := configloader.GetOrDefaultString(logRootString, "")
	if level == "" {
		logRootString = "logging.level.ROOT"
		level = configloader.GetOrDefaultString(logRootString, "")
	}
	if level == "" {
		logRootString = "log.level"
		level = configloader.GetOrDefaultString(logRootString, defaultValue)
	}
	return level
}

func GetLogger(name string) Logger {
	once.Do(watch)
	if l, ok := registeredLoggers.Load(name); ok {
		return l.(*logger)
	}
	l := new(logger)
	l.name = name
	l.mu = lock.NewChanMutex()
	maxLvl := readLvlFromConfig(name)
	if lvl, ok := lvlFromString(maxLvl); ok {
		l.maxLvl = lvl
	} else {
		l.maxLvl = defaultMaxLevel
		l.Warn("wrong log level logFormat: %s, falling to '"+defaultMaxLevel.String()+"'", maxLvl)
	}
	registeredLoggers.Store(name, l)
	return l
}

// GetFieldLogger returns the same logger GetLogger would return, typed so the structured-field
// methods are available. Registering and level resolution are identical; only the static type
// differs.
//
//	-var log = logging.GetLogger("orders")
//	+var log = logging.GetFieldLogger("orders")
func GetFieldLogger(name string) FieldLogger {
	return GetLogger(name).(*logger)
}

// Fields adapts an existing Logger to the structured-field API. Prefer GetFieldLogger; use this
// when you only hold a Logger, for example one injected as a dependency or stored in a package
// variable declared as logging.Logger.
//
// For loggers created by this package it is a plain type assertion. For a foreign implementation
// -- a downstream mock or test double -- it returns an adapter that renders fields into the
// message text and forwards to the printf-style methods, so this never panics.
func Fields(l Logger) FieldLogger {
	if fl, ok := l.(FieldLogger); ok {
		return fl
	}
	return &noFieldLogger{Logger: l}
}

func GetLogLevels() LogLevels {
	logLevels := make(LogLevels)
	rootLvl, _ := lvlFromString(readLvlFromConfig(""))
	logLevels["ROOT"] = strings.ToUpper(rootLvl.String())
	registeredLoggers.Range(func(key, value any) bool {
		logLevels[key.(string)] = strings.ToUpper(value.(Logger).GetLevel().String())
		return true
	})
	return logLevels
}

// root returns the registered logger this one derives from, which owns all mutable configuration.
// For a registered logger that is itself.
func (l *logger) root() *logger {
	if l.base != nil {
		return l.base
	}
	return l
}

func (l *logger) GetLevel() Lvl {
	return l.readMaxLvlWithRLock()
}

// SetLevel updates the level of the underlying registered logger. Called on a logger derived from
// With, it changes the parent too -- a derived logger is a view of its parent, not an independent
// copy.
func (l *logger) SetLevel(maxLvl Lvl) {
	root := l.root()
	root.rwLockForMaxLvl.Lock()
	root.maxLvl = maxLvl
	root.rwLockForMaxLvl.Unlock()
}

func (l *logger) SetLogFormat(logFormat func(r *Record) []byte) {
	l.root().logFormat.Store(&logFormat)
}

func (l *logger) SetMessageFormat(fn messageFmt) {
	format := &defaultFormat{}
	format.SetMessageFormat(fn)
	var logFormat LogFormatFunc = format.format
	l.root().logFormat.Store(&logFormat)
}

// SetLogFormat installs a formatter for every logger that has no formatter of its own. Doing so
// marks the format as explicitly chosen, so a later configuration refresh will not replace it.
func SetLogFormat(format func(r *Record) []byte) {
	globalLogFormat.Store(&format)
	globalFormatExplicit.Store(true)
}

// SetOutput sets this logger's destination, overriding the global one. Applies to the underlying
// registered logger, so loggers derived with With share it.
func (l *logger) SetOutput(w io.Writer) {
	root := l.root()
	if w == nil {
		root.out.Store(nil)
		return
	}
	root.out.Store(&w)
}

// writer resolves the destination at write time: per-logger override, then the global one, then
// os.Stdout. Nothing is captured at construction, so reassigning os.Stdout still takes effect.
func (l *logger) writer() io.Writer {
	if w := l.root().out.Load(); w != nil {
		return *w
	}
	return resolveGlobalWriter()
}

// format resolves which formatter renders the record. Each step is a single atomic load, so a
// concurrent format switch cannot tear a line: a call resolves one formatter and produces one
// complete line with it.
func (l *logger) format(r *Record) []byte {
	if f := l.root().logFormat.Load(); f != nil {
		return (*f)(r)
	}
	if f := globalLogFormat.Load(); f != nil {
		return (*f)(r)
	}
	return formatFuncFor(GetOutputFormat())(r)
}

// Returns the name of a Lvl
func (l Lvl) String() string {
	switch l {
	case LvlDebug:
		return "debug"
	case LvlInfo:
		return "info"
	case LvlWarn:
		return "warn"
	case LvlError:
		return "error"
	case LvlCrit:
		return "fatal"
	default:
		panic("bad level")
	}
}

// lvlFromString returns the appropriate Lvl from a string name.
// Useful for parsing command line args and configuration files.
func lvlFromString(lvlString string) (Lvl, bool) {
	lvlLowCase := strings.ToLower(lvlString)
	switch lvlLowCase {
	case "debug":
		return LvlDebug, true
	case "info":
		return LvlInfo, true
	case "warn":
		return LvlWarn, true
	case "error":
		return LvlError, true
	case "fatal":
		return LvlCrit, true
	default:
		return defaultMaxLevel, false
	}
}

func setLogLevel(lvl string, packageName string) error {
	desiredLogger, loggerIsFound := registeredLoggers.Load(packageName)
	if !loggerIsFound {
		return errors.New("Logger with name " + packageName + " not found")
	}
	if newLevel, isLevelExists := lvlFromString(lvl); isLevelExists {
		desiredLogger.(*logger).SetLevel(newLevel)
		registeredLoggers.Store(packageName, desiredLogger)
		return nil
	}
	return errors.New("Can't set lvl " + lvl + " for logger " + packageName)
}

// mutexes are used to guarantee that
// only a single Log operation can proceed at a Time. It's necessary
// for thread-safe concurrent writes.
func (l *logger) log(ctx context.Context, lvl Lvl, wr io.Writer, sFormat string, args ...interface{}) error {
	if lvl > l.readMaxLvlWithRLock() {
		return nil
	}
	return l.emit(&Record{
		PackageName: l.name,
		Time:        time.Now(),
		Lvl:         lvl,
		Message:     fmt.Sprintf(sFormat, args...),
		Ctx:         ctx,
		Fields:      l.fields,
	}, wr)
}

// logw is the structured-field write path. It deliberately does not go through log(): msg is a
// literal, and log() would run it through fmt.Sprintf, turning a message such as "100% done" into
// "100%!d(MISSING)one".
func (l *logger) logw(ctx context.Context, lvl Lvl, msg string, extra []Field) error {
	if lvl > l.readMaxLvlWithRLock() {
		return nil
	}
	return l.emit(&Record{
		PackageName: l.name,
		Time:        time.Now(),
		Lvl:         lvl,
		Message:     msg,
		Ctx:         ctx,
		Fields:      concatFields(l.fields, extra),
	}, l.writer())
}

// emit formats and writes a record. Both the printf and the structured paths funnel through here
// so the deadlock guard exists in exactly one place.
//
// The write mutex belongs to the registered logger, so loggers derived with With serialise against
// their parent rather than interleaving with it.
func (l *logger) emit(r *Record, wr io.Writer) error {
	mu := l.root().mu
	if mu.TryLockWithTimeout(5 * time.Second) {
		defer mu.Unlock()
		_, err := wr.Write(l.format(r))
		return err
	}

	// The lock could not be acquired, which in practice means a custom formatter logged from
	// inside itself. Report it and still emit the record, using a pristine default formatter so
	// the offending format function is not invoked a second time.
	defaultFormatForError := new(defaultFormat)
	printErrorLogInDefaultFormat(wr, *r, *defaultFormatForError)
	_, err := wr.Write(defaultFormatForError.format(r))
	return err
}

func (l *logger) Debug(format string, args ...interface{}) {
	l.log(nil, LvlDebug, l.writer(), format, args...)
}
func (l *logger) Debugf(format string, args ...interface{}) {
	l.Debug(format, args...)
}
func (l *logger) DebugC(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LvlDebug, l.writer(), format, args...)
}
func (l *logger) Info(format string, args ...interface{}) {
	l.log(nil, LvlInfo, l.writer(), format, args...)
}
func (l *logger) Infof(format string, args ...interface{}) {
	l.Info(format, args...)
}
func (l *logger) InfoC(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LvlInfo, l.writer(), format, args...)
}
func (l *logger) Warn(format string, args ...interface{}) {
	l.log(nil, LvlWarn, l.writer(), format, args...)
}
func (l *logger) Warnf(format string, args ...interface{}) {
	l.Warn(format, args...)
}
func (l *logger) WarnC(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LvlWarn, l.writer(), format, args...)
}
func (l *logger) Error(format string, args ...interface{}) {
	l.log(nil, LvlError, l.writer(), format, args...)
}
func (l *logger) Errorf(format string, args ...interface{}) {
	l.Error(format, args...)
}
func (l *logger) ErrorC(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LvlError, l.writer(), format, args...)
}
func (l *logger) Panic(format string, args ...interface{}) {
	l.log(nil, LvlCrit, l.writer(), format, args...)
	panic(fmt.Sprintf(format, args...))
}
func (l *logger) Panicf(format string, args ...interface{}) {
	// No panic of its own: Panic already panics, so a second call here was unreachable.
	l.Panic(format, args...)
}
func (l *logger) PanicC(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LvlCrit, l.writer(), format, args...)
	panic(fmt.Sprintf(format, args...))
}

// readMaxLvlWithRLock reads the level from the underlying registered logger. A logger derived with
// With has no level of its own -- reading its zero-valued field would silently filter every record
// above fatal.
func (l *logger) readMaxLvlWithRLock() Lvl {
	root := l.root()
	root.rwLockForMaxLvl.RLock()
	defer root.rwLockForMaxLvl.RUnlock()
	return root.maxLvl
}

func printErrorLogInDefaultFormat(wr io.Writer, r Record, DefaultFormatForError defaultFormat) {
	wr.Write(DefaultFormatForError.format(&Record{
		PackageName: constructCallerValue(r.Ctx, r.PackageName),
		Time:        time.Time{},
		Lvl:         1,
		Message: "Possibility of deadlock or circular dependency. " +
			"Perhaps, you use wrong custom log format",
		Ctx: nil,
	}))
}
