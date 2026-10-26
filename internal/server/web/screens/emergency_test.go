package screens_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/vasyakrg/tgproxy-server/internal/server/installer"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

type agEmergency struct {
	mu    sync.Mutex
	calls [][2]string
	err   error
}

func (f *agEmergency) EmergencyUpdate(_ context.Context, id, version string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [2]string{id, version})
	if f.err != nil {
		return "", f.err
	}
	return "01EMEREMEREMEREMEREMEREM", nil
}

func TestEmergencyMenuOnlyForAgentsWithSSHTarget(t *testing.T) {
	a := newAgFx(t, agOpts{emergency: true})
	_, body, _ := a.call("GET", "/agents/fra-1/more", nil, true)
	contains(t, "more", body, "Аварийное обновление по SSH…", `hx-get="/agents/fra-1/emergency"`)
	_, body, _ = a.call("GET", "/agents/hel-1/more", nil, true)
	if strings.Contains(body, "Аварийное обновление") {
		t.Errorf("пункт показан агенту без SSH-цели:\n%s", body)
	}
	b := newAgFx(t, agOpts{})
	_, body, _ = b.call("GET", "/agents/fra-1/more", nil, true)
	if strings.Contains(body, "Аварийное обновление") {
		t.Errorf("пункт показан без настроенного установщика:\n%s", body)
	}
}

func TestEmergencyConfirmAndStart(t *testing.T) {
	a := newAgFx(t, agOpts{emergency: true})
	code, body, _ := a.call("GET", "/agents/fra-1/emergency", nil, true)
	if code != 200 {
		t.Fatalf("%d", code)
	}
	contains(t, "confirm", body, "Аварийное обновление по SSH?", `action="/agents/fra-1/emergency"`, `name="confirm" value="yes"`, "v1.4.1", "Обновить по SSH")
	if c, _, _ := a.call("GET", "/agents/hel-1/emergency", nil, true); c != http.StatusUnprocessableEntity {
		t.Errorf("агент без SSH-цели: %d", c)
	}

	// Без подтверждения ничего не запускается.
	if c, _, _ := a.call("POST", "/agents/fra-1/emergency", url.Values{}, true); c != http.StatusBadRequest {
		t.Fatalf("без confirm: %d", c)
	}
	if len(a.emerg.calls) != 0 {
		t.Fatalf("запущено без подтверждения: %v", a.emerg.calls)
	}

	code, _, hdr := a.call("POST", "/agents/fra-1/emergency", url.Values{"confirm": {"yes"}}, true)
	if code != 200 || hdr.Get("HX-Redirect") != "/agents/new/jobs/01EMEREMEREMEREMEREMEREM" {
		t.Fatalf("%d %v", code, hdr)
	}
	if len(a.emerg.calls) != 1 || a.emerg.calls[0] != [2]string{"fra-1", "1.4.1"} {
		t.Fatalf("calls %v", a.emerg.calls)
	}
	au := a.audit()
	if len(au) != 1 || au[0].Action != api.AuditAgentEmergency || au[0].Target != "fra-1" || au[0].Actor != "alice" {
		t.Fatalf("audit %+v", au)
	}

	a.emerg.err = installer.ErrNoSSHTarget
	code, body, _ = a.call("POST", "/agents/fra-1/emergency", url.Values{"confirm": {"yes"}}, true)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%d", code)
	}
	contains(t, "err", body, "нет сохранённой SSH-цели")
}

func TestEmergencyNotConfigured(t *testing.T) {
	a := newAgFx(t, agOpts{})
	if c, _, _ := a.call("POST", "/agents/fra-1/emergency", url.Values{"confirm": {"yes"}}, true); c != http.StatusNotImplemented {
		t.Errorf("POST: %d", c)
	}
}

func TestEmergencyJobPage(t *testing.T) {
	a := newAgFx(t, agOpts{emergency: true})
	a.inst.status = installer.JobStatus{
		ID: "J1", Kind: installer.JobKindEmergency, AgentID: "fra-1", Host: "185.12.4.10:22", State: store.InstallRunning, CreatedAt: agNow,
		Steps: []installer.StepStatus{{Key: "ssh", Label: "SSH-подключение под tgproxy-deploy, ключ хоста сверен", Status: "running"}},
	}
	_, body, _ := a.call("GET", "/agents/new/jobs/J1", nil, false)
	contains(t, "job", body, "Аварийное обновление fra-1", `data-step="ssh" data-status="running"`, "Агент обновлён и отвечает по mTLS")
	if strings.Contains(body, "Новый агент") {
		t.Errorf("страница выглядит как установка нового агента:\n%s", body)
	}
}
