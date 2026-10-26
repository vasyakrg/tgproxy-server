package tgapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	tgapi.WriteError(rec, http.StatusBadGateway, "tgproxy: no healthy agents", 0)
	if rec.Code != 502 || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("code=%d headers=%v", rec.Code, rec.Header())
	}
	want := `{"ok":false,"error_code":502,"description":"tgproxy: no healthy agents"}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestWriteErrorRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	tgapi.WriteError(rec, 429, "Too Many Requests: retry after 7", 7)
	var env tgapi.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.ErrorCode != 429 || env.Parameters == nil || env.Parameters.RetryAfter != 7 {
		t.Fatalf("%+v", env)
	}
	if rec.Header().Get("Retry-After") != "7" {
		t.Fatal("Retry-After header")
	}
}
