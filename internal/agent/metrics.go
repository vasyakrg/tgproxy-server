package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Метки code_class помимо "Nxx".
const codeClassProxyErr = "proxy_err"

// Направления трафика для UpstreamBytes.
const (
	DirUp   = "up"   // тело запроса в Telegram
	DirDown = "down" // тело ответа клиенту
)

// Виды ошибок соединения для DialError.
const (
	DialDNS     = "dns"
	DialRefused = "refused"
	DialTimeout = "timeout"
	DialTLS     = "tls"
	DialOther   = "other"
)

// Recorder принимает метрики агента (реализуется internal/metrics.Agent
// напрямую или через адаптер). Вызывается из горячего пути: реализация
// обязана быть быстрой и потокобезопасной.
type Recorder interface {
	// Request учитывает /tg/* запрос: codeClass — 2xx|3xx|4xx|5xx|proxy_err,
	// phase — фаза отказа агента (пусто, если ответил Telegram).
	Request(codeClass, phase string)
	UpstreamDuration(d time.Duration)
	SetInflight(n int)
	UpstreamBytes(direction string, n int)
	DialError(kind string)
}

// MTProtoRecorder — необязательное расширение Recorder для метрик MTProto-релея.
// Если реализация Recorder его поддерживает, релей пишет streams/ошибки dial/байты.
type MTProtoRecorder interface {
	MTProtoStreams(dc, delta int)
	MTProtoDialError(dc int, kind string)
	MTProtoBytes(direction string, n int) // in: клиент → DC, out: DC → клиент
}

type noopMTProtoRecorder struct{}

func (noopMTProtoRecorder) MTProtoStreams(int, int)      {}
func (noopMTProtoRecorder) MTProtoDialError(int, string) {}
func (noopMTProtoRecorder) MTProtoBytes(string, int)     {}

// mtprotoRec возвращает MTProtoRecorder текущего Recorder или no-op.
func (a *Agent) mtprotoRec() MTProtoRecorder {
	if m, ok := a.rec.(MTProtoRecorder); ok {
		return m
	}
	return noopMTProtoRecorder{}
}

type noopRecorder struct{}

func (noopRecorder) Request(string, string)         {}
func (noopRecorder) UpstreamDuration(time.Duration) {}
func (noopRecorder) SetInflight(int)                {}
func (noopRecorder) UpstreamBytes(string, int)      {}
func (noopRecorder) DialError(string)               {}

// WithRecorder подключает приёмник метрик (по умолчанию — no-op).
func WithRecorder(r Recorder) Option {
	return func(a *Agent) {
		if r != nil {
			a.rec = r
		}
	}
}

// codeClass возвращает класс HTTP-статуса ("2xx", "4xx", ...).
func codeClass(code int) string { return strconv.Itoa(code/100) + "xx" }

// dialErrorKind классифицирует ошибку соединения с Telegram.
func dialErrorKind(err error, phase string) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		return DialDNS
	case errors.Is(err, syscall.ECONNREFUSED):
		return DialRefused
	case phase == tgapi.PhaseTimeout || errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return DialTimeout
	case phase == tgapi.PhaseTLS:
		return DialTLS
	default:
		return DialOther
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// countingBody считает прочитанные байты тела запроса без буферизации.
type countingBody struct {
	io.ReadCloser
	n atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// metricsWriter запоминает статус и считает байты ответа. Flush и Unwrap
// сохраняют стриминг (ReverseProxy.FlushInterval = -1) и ResponseController.
type metricsWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *metricsWriter) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *metricsWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *metricsWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *metricsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
