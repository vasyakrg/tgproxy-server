package config

import (
	"net/netip"
	"reflect"
	"strings"
	"time"
)

var (
	prefixType   = reflect.TypeOf(netip.Prefix{})
	durationType = reflect.TypeOf(time.Duration(0))
)

type fieldInfo struct {
	name  string // имя из yaml-тега
	index int
	typ   reflect.Type
}

// yamlFields возвращает экспортируемые поля структуры, участвующие в YAML.
func yamlFields(t reflect.Type) []fieldInfo {
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out = append(out, fieldInfo{name: name, index: i, typ: f.Type})
	}
	return out
}

// isStructNode — вложенная секция конфига (а не скалярное значение вроде netip.Prefix).
func isStructNode(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t != prefixType
}
