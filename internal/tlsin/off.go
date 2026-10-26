package tlsin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/vasyakrg/tgproxy-server/internal/config"
)

// offProvider — TLS терминируется снаружи; сертификата нет.
type offProvider struct{}

func newOff(o *options) (Provider, error) {
	if msg := config.CheckTLSOff(o.trusted, o.proxyListen); msg != "" {
		return nil, fmt.Errorf("tlsin: tls.mode=%s", msg)
	}
	return offProvider{}, nil
}

func (offProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("tlsin: tls is off")
}
func (offProvider) Info() CertInfo         { return CertInfo{Mode: string(config.TLSModeOff)} }
func (offProvider) TLSConfig() *tls.Config { return nil }
func (offProvider) Reload() error          { return nil }
func (offProvider) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
