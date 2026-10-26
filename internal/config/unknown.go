package config

import (
	"fmt"
	"reflect"

	"go.yaml.in/yaml/v3"
)

// findUnknown обходит YAML-дерево параллельно с типом конфигурации и возвращает
// ошибки вида `listen.foo: unknown field (line 5)`. yaml.v3 с KnownFields(true)
// сообщает только строку и имя Go-типа, а не путь — поэтому путь собираем сами.
func findUnknown(n *yaml.Node, t reflect.Type, path string) []error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return findUnknown(n.Content[0], t, path)
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case isStructNode(t) && n.Kind == yaml.MappingNode:
		fields := map[string]fieldInfo{}
		for _, f := range yamlFields(t) {
			fields[f.name] = f
		}
		var errs []error
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Value == "<<" { // merge key: структуру проверит основной декодер
				continue
			}
			p := join(path, k.Value)
			f, ok := fields[k.Value]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: unknown field (line %d)", p, k.Line))
				continue
			}
			errs = append(errs, findUnknown(n.Content[i+1], f.typ, p)...)
		}
		return errs
	case t.Kind() == reflect.Slice && n.Kind == yaml.SequenceNode:
		var errs []error
		for i, c := range n.Content {
			errs = append(errs, findUnknown(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return errs
	}
	return nil
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
