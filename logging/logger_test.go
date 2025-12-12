package logging

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/viney-shih/go-lock"
)

func TestLogger_SetLevel(t *testing.T) {
	var testLogger logger
	testLogger.SetLevel(2)
	assert.Equal(t, Lvl(2), testLogger.maxLvl)
}

func TestGetLogger_DefaultLevel(t *testing.T) {
	actualLogger := createTestLogger(3, "test")
	testLogger := GetLogger("test")
	loggersEqual(t, &actualLogger, testLogger)
}

func TestGetLogger_ReadFromEnv_PackageLvl(t *testing.T) {
	os.Setenv("LOG_LEVEL_PACKAGE_TEST_ENV_PACKAGE", "error")
	actualLogger := createTestLogger(1, "test_env_package")
	testLogger := GetLogger("test_env_package")
	loggersEqual(t, &actualLogger, testLogger)
	os.Clearenv()
}

func TestGetLogger_ReadFromEnv_GlobalLvl(t *testing.T) {
	os.Setenv("LOG_LEVEL", "error")
	actualLogger := createTestLogger(1, "test_env_global")
	testLogger := GetLogger("test_env_global")
	loggersEqual(t, &actualLogger, testLogger)
	os.Clearenv()
}

func TestGetLogger_WrongLogLevel(t *testing.T) {
	os.Setenv("LOG_LEVEL_PACKAGE_WRONG_LVL", "unknown")
	actualLogger := createTestLogger(3, "wrong_lvl")
	testLogger := GetLogger("wrong_lvl")
	loggersEqual(t, &actualLogger, testLogger)
	os.Clearenv()
}

func TestGetLogLevels_Env(t *testing.T) {
	os.Setenv("LOG_LEVEL", "error")
	os.Setenv("LOG_LEVEL_PACKAGE_LOGGER_2", "debug")
	GetLogger("logger.1")
	GetLogger("logger.2")
	logLevels := GetLogLevels()
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["ROOT"])
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["logger.1"])
	assert.Equal(t, strings.ToUpper(LvlDebug.String()), logLevels["logger.2"])
	os.Clearenv()
}

func TestGetLogLevels_EnvNew(t *testing.T) {
	os.Setenv("LOG_LEVEL", "info")
	os.Setenv("LOGGING_LEVEL_ROOT", "error")
	os.Setenv("LOG_LEVEL_PACKAGE_LOGGER_2", "fatal")
	os.Setenv("LOGGING_LEVEL_LOGGER_2", "debug")
	GetLogger("logger.1")
	GetLogger("logger.2")
	logLevels := GetLogLevels()
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["ROOT"])
	assert.Equal(t, strings.ToUpper(LvlError.String()), logLevels["logger.1"])
	assert.Equal(t, strings.ToUpper(LvlDebug.String()), logLevels["logger.2"])
	os.Clearenv()
}

func TestGetLogger_InitedConfigLoader(t *testing.T) {
	testYamlParams := configloader.YamlPropertySourceParams{ConfigFilePath: "./testdata/application.yaml"}
	configloader.InitWithSourcesArray(configloader.BasePropertySources(testYamlParams))
	testLogger := GetLogger("one")
	actualLogger := createTestLogger(0, "one")
	loggersEqual(t, &actualLogger, testLogger)
}

func TestLvl_String(t *testing.T) {
	assert.Equal(t, "fatal", Lvl(0).String())
	assert.Equal(t, "error", Lvl(1).String())
	assert.Equal(t, "warn", Lvl(2).String())
	assert.Equal(t, "info", Lvl(3).String())
	assert.Equal(t, "debug", Lvl(4).String())
	assert.Panics(t, func() { Lvl(-1).String() }, "bad level")
}

func TestFormat(t *testing.T) {
	logger := createTestLogger(3, "test")
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
	logger := createTestLogger(3, "test")
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
	logger := createTestLogger(3, "test")
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
	logger := createTestLogger(3, "test")
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

func createTestLogger(lvl int, name string) logger {
	var logger logger
	logger.maxLvl = Lvl(lvl)
	logger.name = name
	logger.mu = lock.NewChanMutex()
	return logger
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
