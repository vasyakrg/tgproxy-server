package tgapi_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestParseEnvelope(t *testing.T) {
	env, err := tgapi.ParseEnvelope(strings.NewReader(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 5","parameters":{"retry_after":5,"migrate_to_chat_id":-100123}}`), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if env.OK || env.ErrorCode != 429 || env.Parameters == nil || env.Parameters.RetryAfter != 5 || env.Parameters.MigrateToChatID != -100123 {
		t.Fatalf("%+v", env)
	}
	env, err = tgapi.ParseEnvelope(strings.NewReader(`{"ok":true,"result":{"id":1}}`), 4096)
	if err != nil || !env.OK || env.Parameters != nil {
		t.Fatalf("%+v %v", env, err)
	}
}

func TestParseEnvelopeErrors(t *testing.T) {
	if _, err := tgapi.ParseEnvelope(strings.NewReader("<html>"), 100); err == nil {
		t.Fatal("garbage must fail")
	}
	if _, err := tgapi.ParseEnvelope(strings.NewReader(`{"ok":true}`), -5); !errors.Is(err, tgapi.ErrEnvelopeTooLarge) {
		t.Fatalf("negative limit: %v", err)
	}
	if _, err := tgapi.ParseEnvelope(errReader{}, 10); err == nil {
		t.Fatal("read error must propagate")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestParseEnvelopeLimit(t *testing.T) {
	big := `{"ok":true,"result":"` + strings.Repeat("x", 1<<20) + `"}`
	cr := &countingReader{r: strings.NewReader(big)}
	_, err := tgapi.ParseEnvelope(cr, 1024)
	if !errors.Is(err, tgapi.ErrEnvelopeTooLarge) {
		t.Fatalf("err=%v", err)
	}
	if cr.n > 1024+1+4096 { // limit+1 plus at most one internal read buffer
		t.Fatalf("read %d bytes, expected ~limit", cr.n)
	}
	// exactly at the limit is fine
	body := `{"ok":true}`
	if _, err := tgapi.ParseEnvelope(strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
}

func TestIsNotModifiedAndNotFound(t *testing.T) {
	nm := &tgapi.Envelope{ErrorCode: 400, Description: "Bad Request: message is not modified: specified new message content and reply markup are exactly the same"}
	nf := &tgapi.Envelope{ErrorCode: 400, Description: "Bad Request: message to delete not found"}
	other := &tgapi.Envelope{ErrorCode: 400, Description: "Bad Request: chat not found"}
	if !tgapi.IsNotModified(nm) || tgapi.IsNotModified(nf) || tgapi.IsNotModified(other) || tgapi.IsNotModified(nil) {
		t.Fatal("IsNotModified")
	}
	if !tgapi.IsNotFound(nf) || tgapi.IsNotFound(nm) || tgapi.IsNotFound(other) || tgapi.IsNotFound(nil) {
		t.Fatal("IsNotFound")
	}
	if tgapi.IsNotModified(&tgapi.Envelope{OK: true, ErrorCode: 400, Description: "message is not modified"}) {
		t.Fatal("ok=true is never an error")
	}
	if tgapi.IsNotModified(&tgapi.Envelope{ErrorCode: 500, Description: "message is not modified"}) {
		t.Fatal("wrong code")
	}
}
