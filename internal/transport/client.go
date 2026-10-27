// Package transport — канал server → agent за единым интерфейсом
// AgentTransport (docs/architecture.md §4, §4.1). Режим dial реализован
// здесь; reverse добавляется в M5-T8 без изменения интерфейса.
package transport

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// StatusPath — эндпоинт отчётности агента.
const StatusPath = "/_agent/status"

// AgentRef — адресат запроса. URL нужен только для mode=dial.
type AgentRef struct {
	ID   string
	URL  *url.URL
	Mode config.AgentMode
}

// AgentTransport — единый интерфейс связи с агентом.
//
// RoundTrip отправляет req агенту: путь/query берутся из req.URL как есть
// (вызывающий формирует /tg/...), схема и хост — из agent. Тело запроса и
// ответа стримятся без буферизации. Ошибка транспорта возвращается как
// *PhaseError; ошибка отмены ctx — как есть. Вызывающий обязан закрыть
// resp.Body.
type AgentTransport interface {
	RoundTrip(ctx context.Context, agent AgentRef, req *http.Request) (*http.Response, error)
	Status(ctx context.Context, agent AgentRef) (*AgentStatus, error)
}

// AgentStatus — ответ GET /_agent/status.
type AgentStatus struct {
	Version       string            `json:"version"`
	Commit        string            `json:"commit"`
	UptimeS       int64             `json:"uptime_s"`
	Inflight      int               `json:"inflight"`
	RPS1m         float64           `json:"rps_1m"`
	ErrorsByPhase map[string]uint64 `json:"errors_by_phase"`
	UpstreamRTTMs float64           `json:"upstream_rtt_ms"`
	Draining      bool              `json:"draining"`
	CertNotAfter  time.Time         `json:"cert_not_after"`
	// Capabilities — возможности агента ("mtproto/1"); у старых агентов поля нет.
	Capabilities []string `json:"capabilities,omitempty"`
	// MTProto — состояние релея MTProto; nil, если агент его не публикует.
	MTProto *MTProtoStatus `json:"mtproto,omitempty"`
}

// CapMTProto — capability агента: поддержка POST /_agent/mtproto/dc/{dc}.
const CapMTProto = "mtproto/1"

// HasCapability сообщает, объявил ли агент возможность c.
func (s *AgentStatus) HasCapability(c string) bool {
	return s != nil && slices.Contains(s.Capabilities, c)
}

// MTProtoStatus — раздел mtproto в /_agent/status.
type MTProtoStatus struct {
	Streams int `json:"streams"`
	// DC — результат последней TCP-пробы по номеру DC ("2").
	DC map[string]DCStatus `json:"dc"`
}

// DCStatus — доступность DC с агента.
type DCStatus struct {
	Up    bool    `json:"up"`
	RTTMs float64 `json:"rtt_ms"`
}
