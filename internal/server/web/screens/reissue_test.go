package screens_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/server/web/screens"
)

func TestAgentMoreHasReissueButton(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, _ := a.call("GET", "/agents/fra-1/more", nil, true)
	contains(t, "more", body, "Новый токен подключения…", `hx-get="/agents/fra-1/enroll-token"`)
	b := newAgFx(t, agOpts{noEnroll: true})
	_, body, _ = b.call("GET", "/agents/fra-1/more", nil, true)
	if strings.Contains(body, "Новый токен подключения") {
		t.Error("кнопка без настроенных токенов")
	}
	if c, _, _ := b.call("GET", "/agents/fra-1/enroll-token", nil, true); c != 501 {
		t.Errorf("не настроено: %d", c)
	}
}

func TestReissueFormWarnsAboutReverseForDial(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, body, _ := a.call("GET", "/agents/fra-1/enroll-token", nil, true) // dial
	contains(t, "dial", body, "Новый токен подключения: fra-1", "переведён в режим reverse", `name="ttl"`, `hx-post="/agents/fra-1/enroll-token"`, "denylist")
	_, body, _ = a.call("GET", "/agents/waw-1/enroll-token", nil, true) // reverse
	if strings.Contains(body, "переведён в режим reverse") {
		t.Error("предупреждение для reverse-агента")
	}
	if c, _, _ := a.call("GET", "/agents/nope/enroll-token", nil, true); c != 404 {
		t.Errorf("unknown: %d", c)
	}
	if c, _, _ := a.call("GET", "/agents/bad%20id/enroll-token", nil, true); c != 404 {
		t.Errorf("bad id: %d", c)
	}
	if c, _, h := a.call("GET", "/agents/fra-1/enroll-token", nil, false); c != 303 || h.Get("Location") != "/agents" {
		t.Errorf("не htmx: %d %v", c, h)
	}
}

func TestReissueIssueShowsBlock(t *testing.T) {
	a := newAgFx(t, agOpts{})
	code, body, hdr := a.call("POST", "/agents/fra-1/enroll-token", url.Values{"ttl": {"30"}}, true)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	contains(t, "issued", body, "Новый токен для «fra-1» выпущен", "показана один раз", "прежние сертификаты агента будут отозваны",
		`id="enroll-cmd"`, `id="enroll-cmd-installed"`, `id="nat-status"`, `hx-get="/agents/enroll/0000000000000001/status?reissue=1"`,
		"Ожидаем подключения агента «fra-1»", `hx-get="/agents/enroll/0000000000000001/revoke?from=agent"`, `id="reissue-revoke"`, "data-modal-close")
	if !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Error("нет тоста")
	}
	if r := a.issuer.reqs[0]; r.AgentID != "fra-1" || r.TTL != 30*time.Minute || r.CreatedBy != "alice" {
		t.Errorf("req %+v", r)
	}
	// токен в ответе только в командах (один раз), в логах его нет
	if strings.Contains(a.logs.String(), wToken) {
		t.Error("токен в логах")
	}
	// ttl вне диапазона → форма с ошибкой, токен не выпущен
	n := a.issuer.n
	code, body, _ = a.call("POST", "/agents/fra-1/enroll-token", url.Values{"ttl": {"99999"}}, true)
	if code != 422 || !strings.Contains(body, "От 1 минуты до 24 часов") || a.issuer.n != n {
		t.Errorf("ttl: %d %s", code, body)
	}
	// ошибка выпуска не раскрывается
	a.issuer.err = errors.New("db down secret")
	code, body, _ = a.call("POST", "/agents/fra-1/enroll-token", url.Values{"ttl": {"30"}}, true)
	if code != 422 || strings.Contains(body, "secret") || !strings.Contains(body, "Не удалось выпустить токен") {
		t.Errorf("ошибка: %d %s", code, body)
	}
	if c, _, _ := a.call("POST", "/agents/nope/enroll-token", url.Values{"ttl": {"30"}}, true); c != 404 {
		t.Errorf("unknown: %d", c)
	}
}

func TestReissueStatusAndRevokeFromAgent(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, _, _ = a.call("POST", "/agents/fra-1/enroll-token", url.Values{"ttl": {"30"}}, true)
	path := "/agents/enroll/0000000000000001/status?reissue=1"
	_, body, _ := a.call("GET", path, nil, true)
	contains(t, "waiting", body, "Ожидаем подключения агента «fra-1»")

	// подтверждение отзыва — внутри блока; «не отзывать» убирает только подтверждение
	_, body, _ = a.call("GET", "/agents/enroll/0000000000000001/revoke?from=agent", nil, true)
	contains(t, "revoke confirm", body, `name="from" value="agent"`, `name="confirm" value="yes"`, "Не отзывать", `hx-target="#agent-modal-body"`)
	if _, body, _ = a.call("GET", "/agents/enroll/0000000000000001/revoke?from=agent&cancel=1", nil, true); strings.TrimSpace(body) != "" {
		t.Errorf("cancel: %q", body)
	}
	// без confirm — 400
	if c, _, _ := a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"from": {"agent"}}, true); c != 400 {
		t.Errorf("без confirm: %d", c)
	}

	// агент уже подключился по токену: токен использован
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", wToken, a.issuer.n)))
	if _, err := a.st.Enrollments().Consume(context.Background(), h[:], agNow); err != nil {
		t.Fatal(err)
	}
	// «подключился» — только наблюдение ПОСЛЕ погашения; fra-1 «в работе» по старому соединению не считается
	a.fleet.states[0].LastSeen = agNow.Add(-time.Minute)
	_, body, _ = a.call("GET", path, nil, true)
	contains(t, "enrolled", body, "зарегистрирован, ждём первое соединение")
	a.fleet.states[0].LastSeen = agNow.Add(time.Minute)
	_, body, _ = a.call("GET", path, nil, true)
	contains(t, "connected", body, "Агент «fra-1» подключился")
	if strings.Contains(body, "К списку агентов") || strings.Contains(body, "delay:2s") {
		t.Errorf("автопереход из диалога: %s", body)
	}

	// отзыв использованного токена: понятная причина
	code, body, _ := a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"confirm": {"yes"}, "from": {"agent"}}, true)
	if code != 422 {
		t.Fatalf("revoke used: %d %s", code, body)
	}
	contains(t, "used", body, "Токен уже использован: агент «fra-1» зарегистрирован.",
		"перезапустите tgproxy-agent на хосте или выпустите новый токен в меню агента")
}

func TestReissueRevokeFromAgentRefreshesTable(t *testing.T) {
	a := newAgFx(t, agOpts{})
	_, _, _ = a.call("POST", "/agents/fra-1/enroll-token", url.Values{"ttl": {"30"}}, true)
	code, body, hdr := a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"confirm": {"yes"}, "from": {"agent"}}, true)
	if code != 200 || !strings.Contains(body, `hx-swap-oob="true"`) || !strings.Contains(hdr.Get("HX-Trigger"), "ok") {
		t.Fatalf("%d %s %v", code, body, hdr)
	}
	if p, _ := a.st.Enrollments().ListPending(context.Background(), agNow); len(p) != 0 {
		t.Errorf("токен не отозван: %+v", p)
	}
	_, status, _ := a.call("GET", "/agents/enroll/0000000000000001/status?reissue=1", nil, true)
	contains(t, "revoked", status, "Токен отозван или удалён.", "Новый токен — в меню агента")
}

func TestWizardRevokeUsedTokenMessage(t *testing.T) {
	a := newAgFx(t, agOpts{})
	a.issueNAT(t, true) // токен «waw-2» погашен
	st := agState("waw-2", "reverse", true, "v1.4.1", 80)
	st.Agent.CreatedAt = agNow.Add(time.Second)
	a.fleet.states = append(a.fleet.states, st)
	code, body, _ := a.call("POST", "/agents/enroll/0000000000000001/revoke", url.Values{"confirm": {"yes"}}, true)
	if code != 422 {
		t.Fatalf("%d %s", code, body)
	}
	contains(t, "used", body, "Токен уже использован: агент «waw-2» зарегистрирован.")
}

func TestReissueGolden(t *testing.T) {
	golden(t, "agent_reissue_form", screens.ReissueForm(screens.ReissueFormVM{ID: "fra-1", Name: "fra-1", TTL: 60, ToReverse: true}))
	golden(t, "agent_reissue_form_reverse", screens.ReissueForm(screens.ReissueFormVM{ID: "waw-1", Name: "waw-1", TTL: 60}))
	golden(t, "enroll_status_reissue_connected", screens.NATStatus(screens.EnrollStatusVM{ID: natStatusID, State: "connected", Name: "fra-1", AgentID: "fra-1", Reissue: true}))
	golden(t, "enroll_status_reissue_expired", screens.NATStatus(screens.EnrollStatusVM{ID: natStatusID, State: "expired", Name: "fra-1", AgentID: "fra-1", Reissue: true}))
}
