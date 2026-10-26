package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// ServerTLSConfig — конфиг TLS-стороны, принимающей соединение, с
// обязательным клиентским сертификатом. verify (VerifyAgentPeer/
// VerifyServerPeer) проверяет идентичность клиента.
func ServerTLSConfig(cert tls.Certificate, ca *x509.CertPool, verify func(tls.ConnectionState) error) (*tls.Config, error) {
	if ca == nil || verify == nil {
		return nil, errors.New("pki: ca pool and verify func are required")
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        ca,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		NextProtos:       []string{"h2"},
		VerifyConnection: verify,
	}, nil
}

// ClientTLSConfig — конфиг TLS-стороны, инициирующей соединение. Сертификаты
// пиров не содержат DNS-имён (идентичность — URI SAN), поэтому стандартная
// проверка имени отключена, а цепочка и SAN проверяются в verify, который
// ОБЯЗАТЕЛЕН.
func ClientTLSConfig(cert tls.Certificate, ca *x509.CertPool, verify func(tls.ConnectionState) error) (*tls.Config, error) {
	if ca == nil || verify == nil {
		return nil, errors.New("pki: ca pool and verify func are required")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca,
		NextProtos:   []string{"h2"},
		// Проверка цепочки и идентичности выполняется в VerifyConnection.
		InsecureSkipVerify: true, //nolint:gosec // см. комментарий выше
		VerifyConnection:   verify,
	}, nil
}
