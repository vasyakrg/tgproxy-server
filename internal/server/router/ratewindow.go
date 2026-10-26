package router

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/tgapi"
)

const (
	// maxWindow ограничивает окно одного 429: защита от «отравления» памяти
	// и от слишком долгой блокировки чата из-за аномального retry_after.
	maxWindow = time.Hour
	// maxChatIDLen — длиннее chat_id не бывает (@username ≤ 32).
	maxChatIDLen = 128
	// sweepEvery — раз в сколько Set в памяти чистятся истёкшие окна.
	sweepEvery = 1024
)

// Store — хранилище окон 429 (память по умолчанию, redis — M2-T7).
type Store interface {
	// Get возвращает момент окончания окна; ok=false, если окна нет.
	Get(key string) (until time.Time, ok bool)
	// Set записывает окно до until; запись может быть удалена через ttl.
	Set(key string, until time.Time, ttl time.Duration)
}

// MemStore — in-memory Store на sync.Map с ленивой очисткой.
type MemStore struct {
	m     sync.Map // string -> time.Time
	clock func() time.Time
	sets  atomic.Uint64
}

// NewMemStore создаёт хранилище в памяти; clock=nil — time.Now.
func NewMemStore(clock func() time.Time) *MemStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemStore{clock: clock}
}

// Get реализует Store.
func (s *MemStore) Get(key string) (time.Time, bool) {
	v, ok := s.m.Load(key)
	if !ok {
		return time.Time{}, false
	}
	until := v.(time.Time)
	if !until.After(s.clock()) {
		s.m.CompareAndDelete(key, v)
		return time.Time{}, false
	}
	return until, true
}

// Set реализует Store.
func (s *MemStore) Set(key string, until time.Time, _ time.Duration) {
	s.m.Store(key, until)
	if s.sets.Add(1)%sweepEvery == 0 {
		now := s.clock()
		s.m.Range(func(k, v any) bool {
			if !v.(time.Time).After(now) {
				s.m.CompareAndDelete(k, v)
			}
			return true
		})
	}
}

// Windows — окна 429 по (bot, chat): пока окно открыто, сервер отвечает 429
// сам, не нагружая агентов. На здоровье агентов не влияет.
type Windows struct {
	store Store
	clock func() time.Time
}

// NewWindows создаёт Windows; store=nil — память, clock=nil — time.Now.
func NewWindows(store Store, clock func() time.Time) *Windows {
	if clock == nil {
		clock = time.Now
	}
	if store == nil {
		store = NewMemStore(clock)
	}
	return &Windows{store: store, clock: clock}
}

func windowKey(botID int64, chatID string) string {
	return strconv.FormatInt(botID, 10) + "|" + chatID
}

// Check возвращает остаток окна и blocked=true, если окно открыто.
func (w *Windows) Check(botID int64, chatID string) (time.Duration, bool) {
	until, ok := w.store.Get(windowKey(botID, chatID))
	if !ok {
		return 0, false
	}
	left := until.Sub(w.clock())
	if left <= 0 {
		return 0, false
	}
	return left, true
}

// Observe открывает окно по ответу 429 с parameters.retry_after.
// Прочие ответы игнорируются.
func (w *Windows) Observe(botID int64, chatID string, env *tgapi.Envelope) {
	if env == nil || env.OK || env.ErrorCode != http.StatusTooManyRequests ||
		env.Parameters == nil || env.Parameters.RetryAfter <= 0 {
		return
	}
	d := min(time.Duration(env.Parameters.RetryAfter)*time.Second, maxWindow)
	w.store.Set(windowKey(botID, chatID), w.clock().Add(d), d)
}

// ExtractChatID достаёт chat_id из query, JSON, urlencoded или multipart.
// Из тела читается не более limit байт; JSON и urlencoded длиннее limit не
// разбираются. multipart сканируется потоково в пределах limit (chat_id
// обычно идёт до файла). Пустая строка — chat_id не найден.
func ExtractChatID(req *http.Request, body Replayable, limit int64) string {
	if id := cleanChatID(req.URL.Query().Get("chat_id")); id != "" {
		return id
	}
	if body == nil || !body.Replayable() || limit <= 0 {
		return ""
	}
	mt, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	size := body.Size()
	if mt != "multipart/form-data" && (size < 0 || size > limit) {
		return ""
	}
	r, err := body.NewReader()
	if err != nil {
		return ""
	}
	defer func() { _ = r.Close() }()
	lr := io.LimitReader(r, limit)
	switch mt {
	case "application/json":
		return chatIDFromJSON(lr)
	case "application/x-www-form-urlencoded":
		data, err := io.ReadAll(lr)
		if err != nil {
			return ""
		}
		vals, err := url.ParseQuery(string(data))
		if err != nil {
			return ""
		}
		return cleanChatID(vals.Get("chat_id"))
	case "multipart/form-data":
		return chatIDFromMultipart(lr, params["boundary"])
	}
	return ""
}

func chatIDFromJSON(r io.Reader) string {
	var v struct {
		ChatID json.RawMessage `json:"chat_id"`
	}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return ""
	}
	raw := bytes.TrimSpace(v.ChatID)
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return cleanChatID(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	return cleanChatID(n.String())
}

func chatIDFromMultipart(r io.Reader, boundary string) string {
	if boundary == "" {
		return ""
	}
	mr := multipart.NewReader(r, boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			return ""
		}
		if p.FormName() != "chat_id" || p.FileName() != "" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(p, maxChatIDLen+1))
		if err != nil {
			return ""
		}
		return cleanChatID(string(data))
	}
}

func cleanChatID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxChatIDLen {
		return ""
	}
	return s
}
