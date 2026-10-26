package installer

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"golang.org/x/crypto/ssh"
)

//go:embed sudoers.tmpl
var sudoersTmplSrc string

//go:embed agent.yaml.tmpl
var agentTmplSrc string

var (
	sudoersTmpl = template.Must(template.New("sudoers").Parse(sudoersTmplSrc))
	agentTmpl   = template.Must(template.New("agent").Parse(agentTmplSrc))
)

// RenderSudoers возвращает содержимое /etc/sudoers.d/tgproxy-deploy.
func RenderSudoers() []byte {
	var b bytes.Buffer
	_ = sudoersTmpl.Execute(&b, map[string]string{"User": deployUser})
	return b.Bytes()
}

// RenderAgentConfig возвращает /etc/tgproxy/agent.yaml для dial-агента.
func RenderAgentConfig(apiPort int, allowedSAN string) ([]byte, error) {
	if err := validatePort("agent port", apiPort); err != nil {
		return nil, err
	}
	if !sanRe.MatchString(allowedSAN) {
		return nil, fmt.Errorf("installer: некорректный allowed_client_san %q", allowedSAN)
	}
	var b bytes.Buffer
	err := agentTmpl.Execute(&b, map[string]any{
		"Port": apiPort, "CertFile": agentCertPath, "KeyFile": agentKeyPath, "CAFile": caCertPath, "SAN": allowedSAN,
	})
	return b.Bytes(), err
}

// authorizedKeyLine — строка authorized_keys для серверного ключа (без port/agent/pty).
func authorizedKeyLine(pub ssh.PublicKey) []byte {
	return append([]byte("no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty "), ssh.MarshalAuthorizedKey(pub)...)
}
