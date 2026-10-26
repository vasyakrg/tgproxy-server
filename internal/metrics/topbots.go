package metrics

import (
	"sort"
	"sync"
	"time"
)

const (
	topBotsBucket  = 10 * time.Minute
	topBotsBuckets = 144 // 24h
	// DefaultMaxBots — лимит отслеживаемых ботов в окне.
	DefaultMaxBots = 10000
	evictFraction  = 10 // при переполнении вытесняется 1/10 самых редких
)

// BotStat — статистика бота за окно.
type BotStat struct {
	BotID    int64
	Rule     string
	Requests uint64
	Errors   uint64 // коды >= 400 и proxy_err (включая 429)
	R429     uint64
}

type slot struct {
	tick           int32
	req, err, r429 uint32
}

type botEntry struct {
	rule  string
	slots [topBotsBuckets]slot
}

// TopBots — in-memory top-K bot_id за скользящее окно 24ч (бакеты по 10 мин).
//
// Память ограничена: не более maxBots ботов (по умолчанию 10k), ~2.3 КБ на бота,
// т.е. ≤ ~23 МБ. При достижении лимита новый бот вытесняет 10% самых редких
// (по запросам в окне) ботов; вытеснение амортизированно O(1) на Observe.
type TopBots struct {
	mu      sync.Mutex
	maxBots int
	now     func() time.Time
	bots    map[int64]*botEntry
}

// NewTopBots создаёт счётчик; maxBots<=0 → DefaultMaxBots.
func NewTopBots(maxBots int) *TopBots {
	if maxBots <= 0 {
		maxBots = DefaultMaxBots
	}
	return &TopBots{maxBots: maxBots, now: time.Now, bots: make(map[int64]*botEntry)}
}

func (t *TopBots) tick() int32 {
	// 10-минутный тик помещается в int32 на тысячи лет вперёд.
	return int32(t.now().Unix() / int64(topBotsBucket/time.Second)) //nolint:gosec // см. выше
}

// Observe учитывает запрос бота. Безопасен для конкурентного использования.
func (t *TopBots) Observe(botID int64, rule string, code int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk := t.tick()
	e, ok := t.bots[botID]
	if !ok {
		if len(t.bots) >= t.maxBots {
			t.evict(tk)
		}
		e = &botEntry{}
		t.bots[botID] = e
	}
	e.rule = rule
	s := &e.slots[int(tk)%topBotsBuckets]
	if s.tick != tk {
		*s = slot{tick: tk}
	}
	s.req++
	if code == 429 {
		s.r429++
	}
	if code >= 400 || code <= 0 {
		s.err++
	}
}

func (e *botEntry) sum(tk int32) (req, errs, r429 uint64) {
	for i := range e.slots {
		s := &e.slots[i]
		if s.req != 0 && s.tick > tk-topBotsBuckets && s.tick <= tk {
			req += uint64(s.req)
			errs += uint64(s.err)
			r429 += uint64(s.r429)
		}
	}
	return
}

// evict удаляет ботов без активности в окне, а при их нехватке — 1/10 самых редких.
func (t *TopBots) evict(tk int32) {
	type kv struct {
		id  int64
		req uint64
	}
	all := make([]kv, 0, len(t.bots))
	for id, e := range t.bots {
		r, _, _ := e.sum(tk)
		if r == 0 {
			delete(t.bots, id)
			continue
		}
		all = append(all, kv{id, r})
	}
	if len(t.bots) < t.maxBots {
		return
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].req != all[j].req {
			return all[i].req < all[j].req
		}
		return all[i].id < all[j].id
	})
	n := len(all) / evictFraction
	if n < 1 {
		n = 1
	}
	for _, x := range all[:n] {
		delete(t.bots, x.id)
	}
}

// Top возвращает до k ботов по числу запросов за окно (убывание; при равенстве — меньший BotID).
func (t *TopBots) Top(k int) []BotStat {
	if k <= 0 {
		return nil
	}
	t.mu.Lock()
	tk := t.tick()
	out := make([]BotStat, 0, len(t.bots))
	for id, e := range t.bots {
		r, er, r4 := e.sum(tk)
		if r == 0 {
			continue
		}
		out = append(out, BotStat{BotID: id, Rule: e.rule, Requests: r, Errors: er, R429: r4})
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].BotID < out[j].BotID
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// Len возвращает число отслеживаемых ботов (для тестов и самодиагностики).
func (t *TopBots) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.bots)
}
