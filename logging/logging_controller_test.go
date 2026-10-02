package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangeLogLevel(t *testing.T) {
	testLogger := registerTestLogger(t, "c_test")
	body := "{\n    \"lvl\":\"error\",\n    \"packageName\":\"c_test\"\n}"
	request, err := http.NewRequest("GET", "/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	ChangeLogLevel(response, request)
	actualLogger := newTestLogger(t, 1, "c_test")
	loggersEqual(t, actualLogger, testLogger)
}

func TestChangeLogLevel_WithBrokenJson(t *testing.T) {
	body := "{\n \": }"
	request, err := http.NewRequest("GET", "/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	ChangeLogLevel(response, request)
	errStr := "{\"error\":\"Invalid request payload\"}"
	assert.JSONEq(t, errStr, response.Body.String())
}

func postFormat(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	request, err := http.NewRequest("POST", "/api/v3/logging/format", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	ChangeLogFormat(response, request)
	return response
}

func TestChangeLogFormat_ToJSON_TakesEffect(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	response := postFormat(t, `{"format":"json"}`)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.JSONEq(t, `{"format":"json","explicit":true}`, response.Body.String())
	assert.Equal(t, FormatJSON, GetOutputFormat())

	// The switch must apply to records written afterwards, with no restart.
	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	l.Info("after switch")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, "after switch", doc["message"])
}

func TestChangeLogFormat_ToText_TakesEffect(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")
	SetOutputFormat(FormatJSON)

	response := postFormat(t, `{"format":"text"}`)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, FormatText, GetOutputFormat())

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	l.Info("after switch")

	assert.True(t, strings.HasPrefix(buf.String(), "["), buf.String())
}

func TestChangeLogFormat_CaseInsensitiveAndTrimmed(t *testing.T) {
	withCleanLoggingState(t)

	assert.Equal(t, http.StatusOK, postFormat(t, `{"format":"  JSON  "}`).Code)
	assert.Equal(t, FormatJSON, GetOutputFormat())
}

// TestChangeLogFormat_UnknownValue_400_FormatUnchanged pins the deliberate divergence from
// configuration bootstrap: an operator's typo must be reported, not silently swallowed by a
// fallback to text.
func TestChangeLogFormat_UnknownValue_400_FormatUnchanged(t *testing.T) {
	withCleanLoggingState(t)
	SetOutputFormat(FormatJSON)

	response := postFormat(t, `{"format":"yaml"}`)

	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), "unknown log format")
	assert.Equal(t, FormatJSON, GetOutputFormat(), "a rejected request must not change the format")
}

func TestChangeLogFormat_EmptyValue_400(t *testing.T) {
	withCleanLoggingState(t)
	SetOutputFormat(FormatJSON)

	assert.Equal(t, http.StatusBadRequest, postFormat(t, `{"format":""}`).Code)
	assert.Equal(t, FormatJSON, GetOutputFormat())
}

func TestChangeLogFormat_MalformedBody_400(t *testing.T) {
	withCleanLoggingState(t)

	response := postFormat(t, `{ ": }`)

	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.JSONEq(t, `{"error":"Invalid request payload"}`, response.Body.String())
}

func TestChangeLogFormat_EmptyBody_400(t *testing.T) {
	withCleanLoggingState(t)

	assert.Equal(t, http.StatusBadRequest, postFormat(t, "").Code)
}

// TestChangeLogFormat_SurvivesConfigloaderRefresh covers the interaction that makes the endpoint
// usable in production: configuration says one thing, the operator says another, and the operator
// wins until the process restarts.
func TestChangeLogFormat_SurvivesConfigloaderRefresh(t *testing.T) {
	withCleanLoggingState(t)

	require.Equal(t, http.StatusOK, postFormat(t, `{"format":"json"}`).Code)

	applyResolvedFormat() // what an Inited/Refreshed event triggers

	assert.Equal(t, FormatJSON, GetOutputFormat())
}

func TestGetLogFormat_ReportsActiveFormatAndExplicitFlag(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)
	activeFormat.Store(int32(FormatText))

	request, err := http.NewRequest("GET", "/api/v3/logging/format", nil)
	require.NoError(t, err)
	response := httptest.NewRecorder()
	GetLogFormat(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.JSONEq(t, `{"format":"text","explicit":false}`, response.Body.String())

	require.Equal(t, http.StatusOK, postFormat(t, `{"format":"json"}`).Code)

	response = httptest.NewRecorder()
	GetLogFormat(response, request)
	assert.JSONEq(t, `{"format":"json","explicit":true}`, response.Body.String())
}

func TestChangeLogFormat_ConcurrentWithLogging_NoRace(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	l := newTestLogger(t, LvlInfo, "orders")
	l.SetOutput(&syncBuffer{})

	var writers, swapper sync.WaitGroup
	stop := make(chan struct{})

	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			body := `{"format":"json"}`
			if i%2 == 1 {
				body = `{"format":"text"}`
			}
			request, _ := http.NewRequest("POST", "/api/v3/logging/format", strings.NewReader(body))
			ChangeLogFormat(httptest.NewRecorder(), request)
		}
	}()

	for w := 0; w < 8; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < 50; i++ {
				l.InfoW("concurrent", "n", i)
			}
		}()
	}

	writers.Wait()
	close(stop)
	swapper.Wait()
}

func TestChangeLogLevel_WithNonExistingLogger(t *testing.T) {
	testLogger := registerTestLogger(t, "NotExist")
	nBody := "{\n    \"lvl\":\"error\",\n    \"packageName\":\"something\"\n}"
	request, err := http.NewRequest("GET", "/test", strings.NewReader(nBody))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	ChangeLogLevel(response, request)
	actualLogger := newTestLogger(t, 3, "NotExist")
	loggersEqual(t, actualLogger, testLogger)
}
