package app

import (
	"context"
	"strconv"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// windowOpTimeout ограничивает обращение к общему хранилищу окон 429.
const windowOpTimeout = time.Second

// windowStore — адаптер store.RateStateRepo к router.Store (окна 429 общие для
// инстансов при Redis). Значение — момент окончания окна в unix-наносекундах.
// Ошибки хранилища не критичны: окно просто не применяется.
type windowStore struct {
	repo store.RateStateRepo
}

func (w windowStore) Get(key string) (time.Time, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), windowOpTimeout)
	defer cancel()
	rw, err := w.repo.Get(ctx, "w429:"+key)
	if err != nil {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(string(rw.Value), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

func (w windowStore) Set(key string, until time.Time, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), windowOpTimeout)
	defer cancel()
	_ = w.repo.Set(ctx, "w429:"+key, []byte(strconv.FormatInt(until.UnixNano(), 10)), ttl)
}
