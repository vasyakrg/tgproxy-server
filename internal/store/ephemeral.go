package store

import "errors"

// Ephemeral — бэкенд эфемерных данных (Redis): подменяет только сессии и rate-state.
type Ephemeral interface {
	Sessions() SessionRepo
	RateState() RateStateRepo
	Close() error
}

type composite struct {
	Store
	eph Ephemeral
}

func (c composite) Sessions() SessionRepo    { return c.eph.Sessions() }
func (c composite) RateState() RateStateRepo { return c.eph.RateState() }

// Close закрывает оба бэкенда.
func (c composite) Close() error {
	return errors.Join(c.eph.Close(), c.Store.Close())
}

// WithEphemeral возвращает Store, у которого Sessions() и RateState() обслуживает eph,
// а остальное — base.
func WithEphemeral(base Store, eph Ephemeral) Store {
	return composite{Store: base, eph: eph}
}
