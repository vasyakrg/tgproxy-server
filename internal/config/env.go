package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	envPrefix = "TGPROXY_"
	envSep    = "__"
)

// applyEnv накладывает переменные окружения TGPROXY_<SECTION>__<FIELD> на dst
// (указатель на структуру конфигурации). Имя = yaml-путь в верхнем регистре,
// сегменты соединены "__": TGPROXY_LISTEN__PROXY, TGPROXY_TLS__ACME__EMAIL.
// Переопределяются только скаляры, duration, netip.Prefix и списки из них;
// списки структур (agents, access_rules) и секреты (только *_file) — нет.
// Переменная с "__" и неизвестным именем — ошибка (опечатка не должна молча
// игнорироваться).
func applyEnv(dst any, environ []string) error {
	env := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, envPrefix) {
			env[k] = v
		}
	}
	known := map[string]struct{}{}
	var errs []error
	walkEnv(reflect.ValueOf(dst).Elem(), nil, env, known, &errs)

	var unknown []string
	for k := range env {
		if _, ok := known[k]; !ok && strings.Contains(strings.TrimPrefix(k, envPrefix), envSep) {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		errs = append(errs, fmt.Errorf("env %s: unknown override", k))
	}
	return errors.Join(errs...)
}

func walkEnv(v reflect.Value, path []string, env map[string]string, known map[string]struct{}, errs *[]error) {
	for _, f := range yamlFields(v.Type()) {
		fv := v.Field(f.index)
		p := append(append([]string(nil), path...), strings.ToUpper(f.name))
		switch {
		case isStructNode(f.typ):
			walkEnv(fv, p, env, known, errs)
		case f.typ.Kind() == reflect.Slice && isStructNode(f.typ.Elem()):
			// agents, access_rules — только через YAML
		default:
			key := envPrefix + strings.Join(p, envSep)
			known[key] = struct{}{}
			raw, ok := env[key]
			if !ok {
				continue
			}
			if err := setScalar(fv, raw); err != nil {
				*errs = append(*errs, fmt.Errorf("env %s: %w", key, err))
			}
		}
	}
}

func setScalar(v reflect.Value, raw string) error {
	t := v.Type()
	switch {
	case t == durationType:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		v.SetInt(int64(d))
	case t == byteSizeType:
		b, err := ParseByteSize(raw)
		if err != nil {
			return err
		}
		v.SetInt(int64(b))
	case t == prefixType:
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(p))
	case t.Kind() == reflect.String:
		v.SetString(raw)
	case t.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		v.SetBool(b)
	case t.Kind() == reflect.Int || t.Kind() == reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)
	case t.Kind() == reflect.Float64:
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return err
		}
		v.SetFloat(f)
	case t.Kind() == reflect.Slice:
		parts := splitList(raw)
		out := reflect.MakeSlice(t, 0, len(parts))
		for _, part := range parts {
			e := reflect.New(t.Elem()).Elem()
			if err := setScalar(e, part); err != nil {
				return fmt.Errorf("%q: %w", part, err)
			}
			out = reflect.Append(out, e)
		}
		v.Set(out)
	default:
		return fmt.Errorf("unsupported type %s", t)
	}
	return nil
}

func splitList(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// osEnviron вынесен для тестов.
var osEnviron = os.Environ
