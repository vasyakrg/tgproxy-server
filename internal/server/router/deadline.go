package router

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

// peekLimit — сколько байт тела читаем, чтобы найти timeout у getUpdates.
const peekLimit = 64 << 10

// minAttemptTimeout — минимальный X-TGP-Timeout-Ms, отдаваемый агенту.
const minAttemptTimeout = time.Millisecond

// timeout вычисляет общий бюджет запроса (architecture §3, §6):
// getUpdates — timeout+LongPollExtra, но не больше MaxLongPoll;
// /file/* — MaxLongPoll (если он больше Budget); прочие — Budget.
func (r *Router) timeout(req *http.Request, body Replayable, route tgapi.Route) time.Duration {
	rc := r.cfg.Router
	switch {
	case tgapi.IsLongPoll(route.Method):
		secs := pollTimeout(req, body)
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
// JSON/urlencoded тела (из буфера, только replayable и ≤ peekLimit).
// multipart не разбираем.
func pollTimeout(req *http.Request, body Replayable) int {
	if v := req.URL.Query().Get("timeout"); v != "" {
		return parseSecs(v)
	}
	if body == nil || !body.Replayable() || body.Size() <= 0 || body.Size() > peekLimit {
		return 0
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	isJSON := strings.HasPrefix(ct, "application/json")
	isForm := strings.HasPrefix(ct, "application/x-www-form-urlencoded")
	if !isJSON && !isForm {
		return 0
	}
	rd, err := body.NewReader()
	if err != nil {
		return 0
	}
	defer func() { _ = rd.Close() }()
	data, err := io.ReadAll(io.LimitReader(rd, peekLimit))
	if err != nil {
		return 0
	}
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

// remaining — остаток бюджета по часам роутера.
func (c *call) remaining() time.Duration {
	return c.budget - c.r.clock().Sub(c.start)
}

// sleepCtx — стандартный sleep с отменой по ctx.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
