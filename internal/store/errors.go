package store

import "errors"

var (
	// ErrNotFound — запись не найдена (или истекла).
	ErrNotFound = errors.New("store: not found")
	// ErrConflict — нарушение уникальности (id, имя, хеш ключа).
	ErrConflict = errors.New("store: conflict")
	// ErrInvalid — модель не прошла валидацию.
	ErrInvalid = errors.New("store: invalid")
)
