// Package router выбирает агента и отправляет ему запрос. В M1 — одна
// попытка и один агент (первый из конфига); структура под ретраи и
// балансировку (M2) заложена в Do/attempt.
package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// Upstream — транспорт до агента (адаптер к internal/transport делает wiring).
// req несёт только путь и query (URL.Path/RawQuery), заголовки и тело;
// схему и адрес выбирает реализация по agentID.
type Upstream interface {
	RoundTrip(ctx context.Context, agentID string, req *http.Request) (*http.Response, error)
}

// Описания ошибок, отдаваемых ботам.
const (
	DescNoAgents = "tgproxy: no healthy agents"
	DescTimeout  = "tgproxy: upstream timeout"
)

// Error — ошибка маршрутизации с готовым HTTP-статусом для бота.
type Error struct {
	Status int
	Desc   string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Desc + ": " + redact.String(e.Err.Error())
	}
	return e.Desc
}

// Unwrap возвращает причину.
func (e *Error) Unwrap() error { return e.Err }

// HTTPStatus — код ответа боту.
func (e *Error) HTTPStatus() int { return e.Status }

// Description — описание в формате Telegram.
func (e *Error) Description() string { return e.Desc }

// peekLimit — сколько байт тела читаем, чтобы найти timeout у getUpdates.
const peekLimit = 64 << 10

// Router отправляет запросы агентам.
type Router struct {
	cfg *config.ServerConfig
	up  Upstream
	log *slog.Logger
}

// New создаёт Router.
func New(cfg *config.ServerConfig, up Upstream, log *slog.Logger) *Router {
	return &Router{cfg: cfg, up: up, log: log}
}

// Do отправляет req агенту. Дедлайн действует до закрытия тела ответа.
// Ошибки: *Error (502/504), либо исходная (например *http.MaxBytesError,
// отмена клиента).
func (r *Router) Do(ctx context.Context, req *http.Request, route tgapi.Route) (*http.Response, error) {
	if len(r.cfg.Agents) == 0 {
		return nil, &Error{Status: http.StatusBadGateway, Desc: DescNoAgents}
	}
	agent := r.cfg.Agents[0].ID
	timeout := r.timeout(req, route)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	resp, err := r.attempt(ctx, agent, 1, timeout, req, route)
	if err != nil {
		cancel()
		return nil, r.mapErr(ctx, err)
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

func (r *Router) attempt(ctx context.Context, agent string, n int, timeout time.Duration,
	req *http.Request, route tgapi.Route) (*http.Response, error) {
	u := &url.URL{Path: tgapi.AgentTGPrefix + strings.TrimPrefix(route.UpstreamPath(), "/"), RawQuery: req.URL.RawQuery}
	// UpstreamPath возвращает экранированный путь; сохраняем его как есть.
	u.RawPath = u.Path
	if p, err := url.PathUnescape(u.Path); err == nil {
		u.Path = p
	}
	body := req.Body
	if body == http.NoBody {
		body = nil
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, u.String(), body)
	if err != nil {
		return nil, err
	}
	out.URL = u
	out.Header = req.Header.Clone()
	out.ContentLength = req.ContentLength
	if body == nil {
		out.ContentLength = 0
	}
	out.Header.Set(tgapi.HeaderTimeoutMs, strconv.FormatInt(timeout.Milliseconds(), 10))
	out.Header.Set(tgapi.HeaderAttempt, strconv.Itoa(n))
	return r.up.RoundTrip(ctx, agent, out)
}

func (r *Router) mapErr(ctx context.Context, err error) error {
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &mb):
		return err
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return &Error{Status: http.StatusGatewayTimeout, Desc: DescTimeout, Err: err}
	case errors.Is(err, context.Canceled):
		return err
	}
	r.log.Warn("upstream failed", "error", redact.Error(err))
	return &Error{Status: http.StatusBadGateway, Desc: DescNoAgents, Err: err}
}

// timeout вычисляет дедлайн запроса.
func (r *Router) timeout(req *http.Request, route tgapi.Route) time.Duration {
	rc := r.cfg.Router
	switch {
	case tgapi.IsLongPoll(route.Method):
		secs := r.pollTimeout(req)
		d := time.Duration(secs)*time.Second + rc.LongPollExtra
		if rc.MaxLongPoll > 0 && d > rc.MaxLongPoll {
			d = rc.MaxLongPoll
		}
		return d
	case route.IsFile:
		// скачивание файла может быть дольше бюджета обычного метода
		if rc.MaxLongPoll > rc.Budget {
			return rc.MaxLongPoll
		}
	}
	return rc.Budget
}

// pollTimeout достаёт параметр timeout getUpdates из query либо из
// JSON/urlencoded тела (тело читается с лимитом и восстанавливается).
// multipart не разбираем.
func (r *Router) pollTimeout(req *http.Request) int {
	if v := req.URL.Query().Get("timeout"); v != "" {
		return parseSecs(v)
	}
	if req.Body == nil || req.Body == http.NoBody {
		return 0
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	isJSON := strings.HasPrefix(ct, "application/json")
	isForm := strings.HasPrefix(ct, "application/x-www-form-urlencoded")
	if !isJSON && !isForm {
		return 0
	}
	orig := req.Body
	data, _ := io.ReadAll(io.LimitReader(orig, peekLimit)) // ошибка вернётся при повторном чтении orig
	req.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), orig), orig}
	if isForm {
		q, err := url.ParseQuery(string(data))
		if err != nil {
			return 0
		}
		return parseSecs(q.Get("timeout"))
	}
	var b struct {
		Timeout json.Number `json:"timeout"`
	}
	if json.Unmarshal(data, &b) != nil {
		return 0
	}
	return parseSecs(b.Timeout.String())
}

func parseSecs(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return min(n, 3600)
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
