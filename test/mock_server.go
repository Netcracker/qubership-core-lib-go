package test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var (
	logger       = logging.GetLogger("test")
	mockHandlers []mockHandler
	mockServer   *httptest.Server
	started      = false
)

type mockHandler struct {
	pathMatcher func(path string) bool
	handle      func(w http.ResponseWriter, r *http.Request)
}

func StartMockServer() {
	if !started {
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestPath := r.URL.Path
			for _, handler := range mockHandlers {
				if handler.pathMatcher(requestPath) {
					handler.handle(w, r)
					return
				}
			}
		}))
		started = true
	} else {
		logger.Error("Can't start mock server - it is already running")
	}
}

func StopMockServer() {
	mockServer.Close()
	ClearHandlers()
	started = false
}

func AddHandler(pathMatcher func(string) bool, handler func(http.ResponseWriter, *http.Request)) {
	mockHandlers = append(mockHandlers, mockHandler{
		pathMatcher: pathMatcher,
		handle:      handler,
	})
}

func ClearHandlers() {
	mockHandlers = nil
}

func Contains(submatch string) func(string) bool {
	return func(path string) bool {
		return strings.Contains(path, submatch)
	}
}

func GetMockServerUrl() string {
	return mockServer.URL
}

func IsMockServerStarted() bool {
	return started
}
