package pki

import (
	"crypto/x509"
	"time"
)

// DueForRotation сообщает, что сертификат прожил не менее 2/3 срока
// (NotAfter-NotBefore) и пора выпускать новый. NotBefore у выпущенных
// сертификатов смещён на skew назад, это учтено в пределах допуска теста.
func DueForRotation(cert *x509.Certificate, now time.Time) bool {
	life := cert.NotAfter.Sub(cert.NotBefore)
	if life <= 0 {
		return true
	}
	return !now.Before(cert.NotBefore.Add(life * 2 / 3))
}
