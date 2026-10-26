package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Path возвращает путь файла, из которого загружен конфиг агента (пусто, если
// конфиг собран в коде).
func (c *AgentConfig) Path() string { return c.path }

// SetPath задаёт путь файла конфига (для сохранения runtime-изменений).
func (c *AgentConfig) SetPath(p string) { c.path = p }

// SaveAgentConnection атомарно обновляет в YAML-файле агента только поля
// mode и server_url (остальное содержимое и комментарии сохраняются).
// serverURL == "" не трогает существующий server_url.
func SaveAgentConnection(path string, mode AgentMode, serverURL string) error {
	if path == "" {
		return errors.New("agent config file path is unknown")
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- путь конфига агента
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("agent config: parse: %w", err)
	}
	if doc.Kind == 0 { // пустой файл
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("agent config: root is not a mapping")
	}
	setYAMLScalar(root, "mode", string(mode))
	if serverURL != "" {
		setYAMLScalar(root, "server_url", serverURL)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("agent config: encode: %w", err)
	}
	_ = enc.Close()
	return writeFileAtomic(path, buf.Bytes(), st.Mode().Perm())
}

func setYAMLScalar(m *yaml.Node, key, val string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val, Style: m.Content[i+1].Style, HeadComment: m.Content[i+1].HeadComment, LineComment: m.Content[i+1].LineComment}
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-config-*")
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("agent config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	ok = true
	return nil
}
