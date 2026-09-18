package logging

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
)

func TestLogger_SetLevel(t *testing.T) {
	var testLogger logger
	testLogger.SetLevel(2)
	assert.Equal(t, Lvl(2), testLogger.maxLvl)
}

func TestGetLogger_DefaultLevel(t *testing.T) {
	actualLogger := newTestLogger(t, 3, "test")
	testLogger := registerTestLogger(t, "test")
	loggersEqual(t, actualLogger, testLogger)
}

func TestGetLogger_ReadFromEnv_PackageLvl(t *testing.T) {
	requireBootstrapConfigPath(t)
	t.Setenv("LOG_LEVEL_PACKAGE_TEST_ENV_PACKAGE", "error")
	actualLogger := newTestLogger(t, 1, "test_env_package")
	testLogger := registerTestLogger(t, "test_env_package")
	loggersEqual(t, actualLogger, testLogger)
}

func TestGetLogger_ReadFromEnv_GlobalLvl(t *testing.T) {
	requireBootstrapConfigPath(t)
	t.Setenv("LOG_LEVEL", "error")
	actualLogger := newTestLogger(t, 1, "test_env_global")
	testLogger := registerTestLogger(t, "test_env_global")
	loggersEqual(t, actualLogger, testLogger)
}

func TestGetLogger_WrongLogLevel(t *testing.T) {
	requireBootstrapConfigPath(t)
	t.Setenv("LOG_LEVEL_PACKAGE_WRONG_LVL", "unknown")
	actualLogger := newTestLogger(t, 3, "wrong_lvl")
	testLogger := registerTestLogger(t, "wrong_lvl")
	loggersEqual(t, actualLogger, testLogger)
}

func TestGetLogLevels_Env(t *testing.T) {
	requireBootstrapConfigPath(t)
	t.Setenv("LOG_LEVEL", "error")
	t.Setenv("LOG_LEVEL_PACKAGE_LOGGER_2", "debug")
	registerTestLogger(t, "logger.1")
	registerTestLogger(t, "logger.2")
	logLevels := GetLogLevels()
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["ROOT"])
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["logger.1"])
	assert.Equal(t, strings.ToUpper(LvlDebug.String()), logLevels["logger.2"])
}

func TestGetLogLevels_EnvNew(t *testing.T) {
	requireBootstrapConfigPath(t)
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOGGING_LEVEL_ROOT", "error")
	t.Setenv("LOG_LEVEL_PACKAGE_LOGGER_2", "fatal")
	t.Setenv("LOGGING_LEVEL_LOGGER_2", "debug")
	registerTestLogger(t, "logger.1")
	registerTestLogger(t, "logger.2")
	logLevels := GetLogLevels()
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["ROOT"])
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["logger.1"])
	assert.Equal(t, strings.ToUpper(LvlDebug.String()), logLevels["logger.2"])
}

// NOTE: this test initialises the process-global configloader and cannot undo it. Every test that
// runs after it resolves configuration through configloader rather than through the os.LookupEnv
// bootstrap path, so tests exercising the env fallback must be declared above it.
func TestGetLogger_InitedConfigLoader(t *testing.T) {
	testYamlParams := configloader.YamlPropertySourceParams{ConfigFilePath: "./testdata/application.yaml"}
	configloader.InitWithSourcesArray(configloader.BasePropertySources(testYamlParams))
	testLogger := registerTestLogger(t, "one")
	actualLogger := newTestLogger(t, 0, "one")
	loggersEqual(t, actualLogger, testLogger)
}

func TestLvl_String(t *testing.T) {
	assert.Equal(t, "fatal", Lvl(0).String())
	assert.Equal(t, "error", Lvl(1).String())
	assert.Equal(t, "warn", Lvl(2).String())
	assert.Equal(t, "info", Lvl(3).String())
	assert.Equal(t, "debug", Lvl(4).String())
	assert.Panics(t, func() { _ = Lvl(-1).String() }, "bad level")
}

func TestFormat(t *testing.T) {
	withCleanLoggingState(t)
	logger := newTestLogger(t, 3, "test")
	message := "This is test record"
	r := Record{
		PackageName: "test",
		Time:        time.Time{},
		Lvl:         0,
		Message:     message,
		Ctx:         nil,
	}
	formatBuffer := logger.format(&r)
	assert.True(t, strings.Contains(string(formatBuffer), message))
	assert.True(t, strings.Contains(string(formatBuffer), "FATAL"))
}

func TestLogger_SetLogFormat(t *testing.T) {
	withCleanLoggingState(t)
	logger := newTestLogger(t, 3, "test")
	message := "This is test record"
	r := Record{
		PackageName: "test",
		Time:        time.Time{},
		Lvl:         0,
		Message:     message,
		Ctx:         nil,
	}
	initialLogFormat := logger.format(&r)
	logger.SetLogFormat(customLogFormat)
	newLogFormat := logger.format(&r)
	assert.NotEqual(t, initialLogFormat, newLogFormat)
}

func TestLogger_SetMessageFormat(t *testing.T) {
	withCleanLoggingState(t)
	logger := newTestLogger(t, 3, "test")
	message := "This is test record"
	r := Record{
		PackageName: "test",
		Time:        time.Time{},
		Lvl:         0,
		Message:     message,
		Ctx:         nil,
	}
	initialLogFormat := logger.format(&r)
	logger.SetMessageFormat(customLogMessage)
	newLogFormat := logger.format(&r)
	assert.NotEqual(t, initialLogFormat, newLogFormat)
}

func TestSetLogFormat(t *testing.T) {
	withCleanLoggingState(t)
	logger := newTestLogger(t, 3, "test")
	message := "This is test record"
	r := Record{
		PackageName: "test",
		Time:        time.Time{},
		Lvl:         0,
		Message:     message,
		Ctx:         nil,
	}
	initialLogFormat := logger.format(&r)
	SetLogFormat(customLogFormat)
	newLogFormat := logger.format(&r)
	assert.NotEqual(t, initialLogFormat, newLogFormat)
}

func customLogFormat(r *Record) []byte {
	var color = 42
	b := &bytes.Buffer{}
	lvl := strings.ToUpper(r.Lvl.String())
	customLogMessage(r, b, color, lvl)

	b.WriteByte('\n')
	return b.Bytes()
}

func customLogMessage(r *Record, b *bytes.Buffer, color int, lvl string) (int, error) {
	TimeFormat := "2006-01-02"
	return fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [packageName=%s] %s",
		r.Time.Format(TimeFormat),
		color,
		lvl,
		"testPackageName",
		r.Message,
	)
}

func loggersEqual(t *testing.T, logger1 Logger, logger2 Logger) {
	assert.Equal(t, logger1.(*logger).readMaxLvlWithRLock(), logger2.(*logger).readMaxLvlWithRLock())
	assert.Equal(t, logger1.(*logger).name, logger2.(*logger).name)
	assert.Equal(t, &logger1.(*logger).logFormat, &logger2.(*logger).logFormat)
}
