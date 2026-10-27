package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// enrolledAgent регистрирует агента обычным токеном и возвращает его id и серийник первого сертификата.
func (f *fixture) enrolledAgent(t *testing.T, name string, weight int) (string, string) {
	t.Helper()
	is, err := f.svc.IssueFor(context.Background(), IssueRequest{Name: name, Weight: weight, InstalledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	w := f.enroll(t, is.Token, goodCSR(t))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var resp Response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	recs, _ := f.st.Certs().ListByAgent(context.Background(), resp.AgentID)
	if len(recs) != 1 {
		t.Fatalf("certs %d", len(recs))
	}
	return resp.AgentID, recs[0].Serial
}

func TestReissueForMissingAgentRejected(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.IssueFor(context.Background(), IssueRequest{AgentID: "ghost", InstalledOnly: true})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v", err)
	}
	if p, _ := f.st.Enrollments().ListPending(context.Background(), f.clock.now()); len(p) != 0 {
		t.Fatalf("токен выпущен для несуществующего агента: %+v", p)
	}
}

func TestReissueWithoutRevokerRejected(t *testing.T) {
	f := newFixture(t)
	id, _ := f.enrolledAgent(t, "nr", 10)
	svc, _ := New(Config{Enrollments: f.st.Enrollments(), Agents: f.st.Agents(), Audit: f.st.Audit(), CA: f.ca, GatewayURL: "https://h:8444", Now: f.clock.now})
	if _, err := svc.IssueFor(context.Background(), IssueRequest{AgentID: id, InstalledOnly: true}); !errors.Is(err, ErrReenrollUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestReenrollKeepsAgentRevokesOldCerts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, oldSerial := f.enrolledAgent(t, "Home NAT", 37)
	// агент переведён в dial с адресом — перевыпуск должен вернуть reverse и очистить URL
	a, _ := f.st.Agents().Get(ctx, id)
	a.Mode, a.URL = store.ModeDial, "https://203.0.113.5:8443"
	if _, err := f.st.Agents().Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	n := len(f.notif)

	is, err := f.svc.IssueFor(ctx, IssueRequest{AgentID: id, Name: "ignored", Weight: 999, CreatedBy: "admin", InstalledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	pend, _ := f.st.Enrollments().ListPending(ctx, f.clock.now())
	if len(pend) != 1 || pend[0].AgentID != id || pend[0].Name != id || pend[0].Weight != 37 {
		t.Fatalf("pending: %+v", pend)
	}
	w := f.enroll(t, is.Token, goodCSR(t))
	if w.Code != http.StatusOK {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	var resp Response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.AgentID != id {
		t.Fatalf("agent id %q want %q", resp.AgentID, id)
	}
	agents, _ := f.st.Agents().List(ctx)
	if len(agents) != 1 {
		t.Fatalf("создан новый агент: %+v", agents)
	}
	got := agents[0]
	if got.Mode != store.ModeReverse || got.URL != "" || got.Weight != 37 || got.Name != "Home NAT" {
		t.Fatalf("agent %+v", got)
	}
	recs, _ := f.st.Certs().ListByAgent(ctx, id)
	if len(recs) != 2 {
		t.Fatalf("certs %d", len(recs))
	}
	if !f.deny.IsDenied(oldSerial) {
		t.Error("старый сертификат не в denylist")
	}
	for _, r := range recs {
		if r.Serial != oldSerial && f.deny.IsDenied(r.Serial) {
			t.Error("новый сертификат отозван")
		}
	}
	if len(f.drops) != 1 || f.drops[0] != id {
		t.Errorf("drops %v", f.drops)
	}
	if len(f.notif) != n {
		t.Errorf("alert agent_enrolled для перевыпуска: %v", f.notif)
	}
	aud, _ := f.st.Audit().List(ctx, store.AuditQuery{})
	var seen bool
	for _, e := range aud {
		if e.Action == "agent.reenroll" && e.Target == id && strings.Contains(e.Detail, "revoked=1") && strings.Contains(e.Detail, "prev_mode=dial") {
			seen = true
		}
	}
	if !seen {
		t.Errorf("нет аудита agent.reenroll: %+v", aud)
	}
	// токен одноразовый
	if w := f.enroll(t, is.Token, goodCSR(t)); w.Code != http.StatusUnauthorized {
		t.Errorf("повторное погашение: %d", w.Code)
	}
}

func TestReenrollAgentRemovedBeforeRedeem(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, _ := f.enrolledAgent(t, "gone", 5)
	is, err := f.svc.IssueFor(ctx, IssueRequest{AgentID: id, InstalledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Agents().Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	certsBefore, _ := f.st.Certs().ListByAgent(ctx, id)
	w := f.enroll(t, is.Token, goodCSR(t))
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "removed") {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	if _, err := f.st.Agents().Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Error("агент воссоздан")
	}
	if after, _ := f.st.Certs().ListByAgent(ctx, id); len(after) != len(certsBefore) {
		t.Error("сертификат выпущен для удалённого агента")
	}
	// токен погашен
	if w := f.enroll(t, is.Token, goodCSR(t)); w.Code != http.StatusUnauthorized {
		t.Errorf("токен не погашен: %d", w.Code)
	}
}

func TestReenrollSignFailureKeepsOldCerts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, oldSerial := f.enrolledAgent(t, "sf", 5)
	svc, _ := New(Config{Enrollments: f.st.Enrollments(), Agents: f.st.Agents(), Audit: f.st.Audit(), CA: failCA{Authority: f.ca}, GatewayURL: "https://h:8444", Now: f.clock.now, Revoker: f.deny})
	is, err := svc.IssueFor(ctx, IssueRequest{AgentID: id, InstalledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	if w := f.enroll(t, is.Token, goodCSR(t)); w.Code != http.StatusInternalServerError {
		t.Fatalf("code %d", w.Code)
	}
	if f.deny.IsDenied(oldSerial) {
		t.Error("старый сертификат отозван при неудачной подписи")
	}
	if _, err := f.st.Agents().Get(ctx, id); err != nil {
		t.Errorf("агент удалён при ошибке перевыпуска: %v", err)
	}
}
