package notify

import (
	"fmt"
	"os"
	"sort"

	"go.yaml.in/yaml/v3"
)

const maxUsersFile = 4 << 20

// Recipient — получатель алертов.
type Recipient struct {
	User       string
	TelegramID int64
}

// usersDoc читает из users-файла (формат Authelia) только нужные поля;
// хеши паролей и TOTP-секреты в память этого пакета не попадают.
type usersDoc struct {
	Users map[string]struct {
		TelegramID int64 `yaml:"telegram_id"`
		Disabled   bool  `yaml:"disabled"`
	} `yaml:"users"`
}

// LoadRecipients читает получателей из users-файла. Пользователи без
// telegram_id (0 или отсутствует) и disabled пропускаются. Результат
// отсортирован по имени пользователя.
func LoadRecipients(usersFile string) ([]Recipient, error) {
	fi, err := os.Stat(usersFile)
	if err != nil {
		return nil, fmt.Errorf("notify: users file: %w", err)
	}
	if fi.Size() > maxUsersFile {
		return nil, fmt.Errorf("notify: users file too large")
	}
	b, err := os.ReadFile(usersFile) // #nosec G304 -- путь из конфигурации администратора
	if err != nil {
		return nil, fmt.Errorf("notify: users file: %w", err)
	}
	var doc usersDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("notify: parse users file: %w", err)
	}
	out := make([]Recipient, 0, len(doc.Users))
	for name, u := range doc.Users {
		if u.TelegramID == 0 || u.Disabled {
			continue
		}
		out = append(out, Recipient{User: name, TelegramID: u.TelegramID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out, nil
}
