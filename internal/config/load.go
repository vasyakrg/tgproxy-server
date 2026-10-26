package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"go.yaml.in/yaml/v3"
)

// minAccessKeyLen — минимальная длина открытого ключа из key_file.
const minAccessKeyLen = 16

// loadable — то, что умеет грузиться через Load.
type loadable[T any] interface {
	*T
	setDefaults()
	normalize()
	resolve() error  // чтение *_file секретов, проверка прав файлов
	validate() error // чистая валидация без IO
}

// Load читает YAML-файл path, накладывает env-override, читает секреты и
// валидирует результат. Приоритет: defaults < YAML < env < *_file.
func Load[T any, P loadable[T]](path string) (*T, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- путь из флага -c
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return parse[T, P](data, path, osEnviron())
}

// LoadServer загружает и валидирует конфигурацию сервера.
func LoadServer(path string) (*ServerConfig, error) { return Load[ServerConfig](path) }

// LoadAgent загружает и валидирует конфигурацию агента.
func LoadAgent(path string) (*AgentConfig, error) { return Load[AgentConfig](path) }

func parse[T any, P loadable[T]](data []byte, source string, environ []string) (*T, error) {
	cfg := new(T)
	p := P(cfg)
	p.setDefaults()

	// 1. YAML, строго. Сначала собственный обход ради пути к полю.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}
	if errs := findUnknown(&root, reflect.TypeOf(cfg).Elem(), ""); len(errs) > 0 {
		return nil, fmt.Errorf("config %s: %w", source, errors.Join(errs...))
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) { // пустой файл = дефолты
		return nil, fmt.Errorf("config %s: %w", source, err)
	}
	p.normalize()

	// 2. env-override.
	if err := applyEnv(cfg, environ); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}

	// 3. секреты из *_file и 4. валидация — ошибки собираем вместе.
	var errs []error
	if err := p.resolve(); err != nil {
		errs = append(errs, err)
	}
	if err := p.validate(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}
	return cfg, nil
}

func (c *ServerConfig) setDefaults() { *c = *DefaultServer() }
func (c *AgentConfig) setDefaults()  { *c = *DefaultAgent() }

func (c *ServerConfig) validate() error { return ValidateServer(c) }
func (c *AgentConfig) validate() error  { return ValidateAgent(c) }

func (c *ServerConfig) resolve() error {
	var errs []error
	secret := func(path, file string, dst *Secret) {
		if file == "" {
			return
		}
		s, err := readSecret(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return
		}
		*dst = s
	}
	secret("notify.bot_token_file", c.Notify.BotTokenFile, &c.Notify.BotToken)
	secret("store.redis_password_file", c.Store.RedisPasswordFile, &c.Store.RedisPassword)
	secret("metrics.bearer_file", c.Metrics.BearerFile, &c.Metrics.Bearer)

	for i := range c.AccessRules {
		r := &c.AccessRules[i]
		p := fmt.Sprintf("access_rules[%d]", i)
		switch {
		case r.KeySHA256 != "" && r.KeyFile != "":
			// взаимоисключение сообщит validate
		case r.KeySHA256 != "":
			if b, err := hex.DecodeString(r.KeySHA256); err == nil && len(b) == sha256.Size {
				r.KeyHash = b
			}
		case r.KeyFile != "":
			var k Secret
			secret(p+".key_file", r.KeyFile, &k)
			if k == "" {
				continue
			}
			if len(k) < minAccessKeyLen {
				errs = append(errs, fmt.Errorf("%s.key_file: key shorter than %d characters", p, minAccessKeyLen))
				continue
			}
			sum := sha256.Sum256([]byte(k.Reveal()))
			r.KeyHash = sum[:]
		}
	}

	// Файлы, которые читают другие пакеты: проверяем только права, если файл есть.
	for _, f := range []struct{ path, file string }{
		{"tls.key_file", c.TLS.KeyFile},
		{"agent_tls.key_file", c.AgentTLS.KeyFile},
		{"pki.kek_file", c.PKI.KEKFile},
	} {
		if err := checkPermIfExists(f.file); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.path, err))
		}
	}
	return errors.Join(errs...)
}

func (c *AgentConfig) resolve() error {
	var errs []error
	if c.Metrics.BearerFile != "" {
		s, err := readSecret(c.Metrics.BearerFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("metrics.bearer_file: %w", err))
		} else {
			c.Metrics.Bearer = s
		}
	}
	if err := checkPermIfExists(c.TLS.KeyFile); err != nil {
		errs = append(errs, fmt.Errorf("tls.key_file: %w", err))
	}
	return errors.Join(errs...)
}
