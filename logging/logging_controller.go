package logging

import (
	"encoding/json"
	"net/http"
)

type changeLevelRequest struct {
	LvlFromRequest string `json:"lvl"`
	PackageName    string `json:"packageName"`
}

func ChangeLogLevel(w http.ResponseWriter, r *http.Request) {
	controllerLogger := GetLogger("logging")
	defer r.Body.Close()
	controllerLogger.Info("Start Change Log Level API call")
	decoder := json.NewDecoder(r.Body)

	var data changeLevelRequest
	if err := decoder.Decode(&data); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	err := setLogLevel(data.LvlFromRequest, data.PackageName)
	if err != nil {
		controllerLogger.Warn("Log Level didn't changed")
		respondWithError(w, http.StatusInternalServerError, err.Error())
	} else {
		controllerLogger.Info("Successfully change logLevel to %s", data.LvlFromRequest)
		respondWithJson(w, http.StatusOK, "Successfully change logLevel")
	}
}

type changeFormatRequest struct {
	Format string `json:"format"`
}

type logFormatResponse struct {
	Format   string `json:"format"`
	Explicit bool   `json:"explicit"`
}

// ChangeLogFormat switches the log format at runtime, the same way ChangeLogLevel switches the log
// level. Mount it as a POST endpoint, for example at /api/v3/logging/format:
//
//	POST {"format":"json"}  ->  200 {"format":"json","explicit":true}
//
// The change takes effect on the next record written; no restart is needed.
//
// A format set through this endpoint is explicit and therefore survives a later configuration
// refresh -- an operator's deliberate switch must not be silently reverted by a config reload.
//
// Like ChangeLogLevel this is an operator endpoint: place it behind the same authorization, since
// an unauthenticated caller could otherwise reshape a service's log stream.
func ChangeLogFormat(w http.ResponseWriter, r *http.Request) {
	controllerLogger := GetLogger("logging")
	defer r.Body.Close()
	controllerLogger.Info("Start Change Log Format API call")
	decoder := json.NewDecoder(r.Body)

	var data changeFormatRequest
	if err := decoder.Decode(&data); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Unlike configuration bootstrap, which falls back to text silently, an unrecognised value
	// here is an error. Answering 200 while leaving the format unchanged would hide the typo.
	format, ok := parseFormat(data.Format)
	if !ok {
		controllerLogger.Warn("Log format didn't change: unknown format %s", data.Format)
		respondWithError(w, http.StatusBadRequest,
			"unknown log format: "+data.Format+", expected 'text' or 'json'")
		return
	}

	SetOutputFormat(format)
	controllerLogger.Info("Successfully change log format to %s", format.String())
	respondWithJson(w, http.StatusOK, logFormatResponse{Format: format.String(), Explicit: true})
}

// GetLogFormat reports the format currently in effect. Mount it as a GET endpoint alongside
// ChangeLogFormat.
//
// The explicit flag says whether the format was chosen deliberately (through this endpoint,
// SetOutputFormat or SetLogFormat) rather than derived from configuration. It is the first thing
// to check when a configured format appears not to take effect: an explicit value always wins over
// configuration.
func GetLogFormat(w http.ResponseWriter, r *http.Request) {
	respondWithJson(w, http.StatusOK, logFormatResponse{
		Format:   GetOutputFormat().String(),
		Explicit: IsOutputFormatExplicit(),
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJson(w, code, map[string]string{"error": msg})
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
