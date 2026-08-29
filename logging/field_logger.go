package logging

import (
	"context"
	"io"
)

// With returns a logger that attaches the given key/value pairs to every record it writes.
//
//	log := logging.GetFieldLogger("orders").With("component", "checkout")
//	log.InfoWC(ctx, "order placed", "order_id", 42)
//	// ... [class=orders] order placed component=checkout order_id=42
//
// The returned logger is not registered: it does not appear in GetLogLevels and is not visited by
// the configuration watcher. Everything mutable -- level, formatter, output, write mutex -- stays
// on the registered logger it derives from, so configuration changes still reach it and SetLevel
// on it affects the parent.
func (l *logger) With(args ...any) FieldLogger {
	extra := argsToFields(args)
	if len(extra) == 0 {
		return l
	}

	derived := &logger{
		name:   l.name,
		base:   l.root(),
		fields: concatFields(l.fields, extra),
	}
	return derived
}

func (l *logger) DebugW(msg string, args ...any) {
	l.logw(nil, LvlDebug, msg, argsToFields(args))
}

func (l *logger) InfoW(msg string, args ...any) {
	l.logw(nil, LvlInfo, msg, argsToFields(args))
}

func (l *logger) WarnW(msg string, args ...any) {
	l.logw(nil, LvlWarn, msg, argsToFields(args))
}

func (l *logger) ErrorW(msg string, args ...any) {
	l.logw(nil, LvlError, msg, argsToFields(args))
}

func (l *logger) PanicW(msg string, args ...any) {
	l.logw(nil, LvlCrit, msg, argsToFields(args))
	panic(msg)
}

func (l *logger) DebugWC(ctx context.Context, msg string, args ...any) {
	l.logw(ctx, LvlDebug, msg, argsToFields(args))
}

func (l *logger) InfoWC(ctx context.Context, msg string, args ...any) {
	l.logw(ctx, LvlInfo, msg, argsToFields(args))
}

func (l *logger) WarnWC(ctx context.Context, msg string, args ...any) {
	l.logw(ctx, LvlWarn, msg, argsToFields(args))
}

func (l *logger) ErrorWC(ctx context.Context, msg string, args ...any) {
	l.logw(ctx, LvlError, msg, argsToFields(args))
}

func (l *logger) PanicWC(ctx context.Context, msg string, args ...any) {
	l.logw(ctx, LvlCrit, msg, argsToFields(args))
	panic(msg)
}

// noFieldLogger adapts a foreign Logger implementation -- typically a downstream mock -- to
// FieldLogger. It cannot attach fields to a Record because it has no access to the write path, so
// it folds them into the message text instead:
//
//	InfoW("order placed", "order_id", 42)  ->  Info("%s", "order placed order_id=42")
//
// The composed text is always passed as an argument to a "%s" format, never as the format itself:
// the underlying methods are printf-style, so a literal '%' in the message would otherwise be
// misread as a verb.
type noFieldLogger struct {
	Logger
	fields []Field
}

var _ FieldLogger = (*noFieldLogger)(nil)

func (n *noFieldLogger) With(args ...any) FieldLogger {
	extra := argsToFields(args)
	if len(extra) == 0 {
		return n
	}
	return &noFieldLogger{Logger: n.Logger, fields: concatFields(n.fields, extra)}
}

// SetOutput is a no-op: a foreign Logger owns its own destination and exposes no way to change it.
func (n *noFieldLogger) SetOutput(io.Writer) {}

func (n *noFieldLogger) compose(msg string, args []any) string {
	return msg + fieldsToMessageSuffix(concatFields(n.fields, argsToFields(args)))
}

func (n *noFieldLogger) DebugW(msg string, args ...any) { n.Logger.Debug("%s", n.compose(msg, args)) }
func (n *noFieldLogger) InfoW(msg string, args ...any)  { n.Logger.Info("%s", n.compose(msg, args)) }
func (n *noFieldLogger) WarnW(msg string, args ...any)  { n.Logger.Warn("%s", n.compose(msg, args)) }
func (n *noFieldLogger) ErrorW(msg string, args ...any) { n.Logger.Error("%s", n.compose(msg, args)) }

func (n *noFieldLogger) PanicW(msg string, args ...any) {
	// Not Logger.Panic: that would panic with the composed text including the rendered fields.
	// Log at the same severity, then panic with the message the caller actually passed.
	n.Logger.Error("%s", n.compose(msg, args))
	panic(msg)
}

func (n *noFieldLogger) DebugWC(ctx context.Context, msg string, args ...any) {
	n.Logger.DebugC(ctx, "%s", n.compose(msg, args))
}

func (n *noFieldLogger) InfoWC(ctx context.Context, msg string, args ...any) {
	n.Logger.InfoC(ctx, "%s", n.compose(msg, args))
}

func (n *noFieldLogger) WarnWC(ctx context.Context, msg string, args ...any) {
	n.Logger.WarnC(ctx, "%s", n.compose(msg, args))
}

func (n *noFieldLogger) ErrorWC(ctx context.Context, msg string, args ...any) {
	n.Logger.ErrorC(ctx, "%s", n.compose(msg, args))
}

func (n *noFieldLogger) PanicWC(ctx context.Context, msg string, args ...any) {
	n.Logger.ErrorC(ctx, "%s", n.compose(msg, args))
	panic(msg)
}
