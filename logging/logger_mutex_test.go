package logging

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"strings"
	"testing"
)

var errorLogger Logger
var errorLog error

func customErrorMessageFormat(r *Record, b *bytes.Buffer, color int, lvl string) (int, error) {
	TimeFormat := "2006-01-02"
	errorLogger.Info("blocking log")
	return fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [requestId=%s] [caller=%s] %s",
		r.Time.Format(TimeFormat),
		color,
		lvl,
		"some-id",
		"main",
		r.Message,
	)
}

func TestLogger_TestMutex(t *testing.T) {
	done := capture()

	errorLogger = GetLogger("logging-mutex")
	errorLogger.SetMessageFormat(customErrorMessageFormat)
	errorLogger.Info("Some test log")

	capturedOutput, _ := done()
	assert.True(t, strings.Contains(capturedOutput, "Possibility of deadlock or circular dependency"))
}

func capture() func() (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	done := make(chan error, 1)
	save := os.Stdout
	os.Stdout = w
	var buf strings.Builder

	go func() {
		_, err := io.Copy(&buf, r)
		r.Close()
		done <- err
	}()

	return func() (string, error) {
		os.Stdout = save
		w.Close()
		err := <-done
		return buf.String(), err
	}
}
