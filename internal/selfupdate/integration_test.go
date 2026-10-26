//go:build integration

package selfupdate_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"
)

// Интеграционный тест в контейнере debian:12: настоящие dpkg и root, подпись minisign
// (ключ тест-генерации вшивается в бинарь через -ldflags), заглушка systemctl.
// Запуск: go test -tags integration -run TestApplyInDebian ./internal/selfupdate/

var ctx = context.Background()

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- тест
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestApplyInDebian(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("нет docker")
	}
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker недоступен")
	}
	goarch := map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[sh(t, "docker", "info", "--format", "{{.Architecture}}")]
	if goarch == "" {
		t.Skip("неподдерживаемая архитектура docker")
	}
	tmp := t.TempDir()

	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubS := pub.String()
	bin := filepath.Join(tmp, "tgproxy")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "-ldflags",
		"-X github.com/vasyakrg/tgproxy-server/internal/release.pubKeysCSV="+pubS+
			" -X github.com/vasyakrg/tgproxy-server/internal/buildinfo.Version=0.1.0", "./cmd/tgproxy")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	name := "tgproxy-it-" + hex.EncodeToString(sum([]byte(tmp))[:4])
	sh(t, "docker", "run", "-d", "--name", name, "debian:12", "sleep", "600")
	if os.Getenv("KEEP") == "" {
		t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run() })
	}
	in := func(script string) string { t.Helper(); return sh(t, "docker", "exec", name, "bash", "-ec", script) }

	in(`umask 022
useradd -r -s /usr/sbin/nologin tgproxy
mkdir -p /var/lib/tgproxy/updates/staged /var/cache/tgproxy/packages/0.1.0
chmod 0755 /var/cache/tgproxy /var/cache/tgproxy/packages /var/cache/tgproxy/packages/0.1.0
chown tgproxy:tgproxy /var/lib/tgproxy /var/lib/tgproxy/updates /var/lib/tgproxy/updates/staged
chmod 0750 /var/lib/tgproxy; chmod 0755 /var/lib/tgproxy/updates/staged
cat > /usr/bin/systemctl <<'SYSEOF'
#!/bin/sh
echo "$@" >> /tmp/systemctl.log
crash() { [ "$(cat /usr/share/tgproxy-ver)" = 0.4.0 ]; }
case "$1" in
show) if crash; then printf 'ActiveState=failed\nNRestarts=3\nActiveEnterTimestampMonotonic=0\n'; else printf 'ActiveState=active\nNRestarts=0\nActiveEnterTimestampMonotonic=1\n'; fi ;;
is-active) ! crash ;;
esac
exit 0
SYSEOF
chmod +x /usr/bin/systemctl
mkdeb() { d=$(mktemp -d); chmod 755 $d; mkdir -p -m 755 $d/DEBIAN $d/usr/share; echo "$1" > $d/usr/share/tgproxy-ver
  printf 'Package: tgproxy\nVersion: %s\nArchitecture: %s\nMaintainer: t <t@t>\nDescription: it\n' "$1" "$(dpkg --print-architecture)" > $d/DEBIAN/control
  dpkg-deb --build $d /root/tgproxy_$1_$(dpkg --print-architecture).deb >/dev/null; }
mkdeb 0.1.0; mkdeb 0.2.0; mkdeb 0.3.0; mkdeb 0.4.0
dpkg -i /root/tgproxy_0.1.0_*.deb >/dev/null
cp /root/tgproxy_0.1.0_*.deb /var/cache/tgproxy/packages/0.1.0/`)
	sh(t, "docker", "cp", bin, name+":/usr/local/bin/tgproxy")

	stage := func(version string, key minisign.PrivateKey) {
		t.Helper()
		in(`install -d -o tgproxy -g tgproxy -m 0755 /var/lib/tgproxy/updates/staged`)
		deb := fmt.Sprintf("tgproxy_%s_%s.deb", version, goarch)
		dst := filepath.Join(tmp, deb)
		sh(t, "docker", "cp", name+":/root/"+deb, dst)
		b, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		checks := []byte(hex.EncodeToString(sum(b)) + "  " + deb + "\n")
		files := map[string][]byte{"checksums.txt": checks, "checksums.txt.minisig": minisign.Sign(key, checks),
			"request": []byte(fmt.Sprintf(`{"version":%q,"component":"agent"}`, version))}
		for n, c := range files {
			p := filepath.Join(tmp, n)
			if err := os.WriteFile(p, c, 0o600); err != nil {
				t.Fatal(err)
			}
			sh(t, "docker", "cp", p, name+":/var/lib/tgproxy/updates/staged/"+n)
		}
		sh(t, "docker", "cp", dst, name+":/var/lib/tgproxy/updates/staged/"+deb)
		in(`chown -R tgproxy:tgproxy /var/lib/tgproxy/updates/staged; chmod 0644 /var/lib/tgproxy/updates/staged/*`)
	}
	apply := func() (string, error) {
		out, err := exec.CommandContext(ctx, "docker", "exec", name, "tgproxy", "update", "apply", "--component", "agent").CombinedOutput()
		return string(out), err
	}

	// Успех: 0.1.0 -> 0.2.0.
	stage("0.2.0", priv)
	if out, err := apply(); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if v := in(`cat /usr/share/tgproxy-ver`); v != "0.2.0" {
		t.Fatalf("версия после обновления = %s", v)
	}
	if r := in(`cat /var/lib/tgproxy/updates/result.json; stat -c ' %U:%G %a' /var/lib/tgproxy/updates/result.json; ls /var/cache/tgproxy/packages /var/cache/tgproxy/packages/0.2.0; test ! -e /var/lib/tgproxy/updates/staged && echo staged-cleaned; stat -c "%U:%G %a" /var/cache/tgproxy/packages`); !strings.Contains(r, `"ok":true`) ||
		!strings.Contains(r, "root:tgproxy 640") || !strings.Contains(r, "prev.deb") || !strings.Contains(r, "checksums.txt.minisig") || !strings.Contains(r, "root:root 755") || !strings.Contains(r, "staged-cleaned") {
		t.Fatalf("результат:\n%s", r)
	}
	if l := in(`cat /tmp/systemctl.log`); !strings.Contains(l, "restart tgproxy-agent") || !strings.Contains(l, "is-active --quiet tgproxy-agent") {
		t.Fatalf("systemctl: %s", l)
	}

	// Агент, который стартует и падает (бинарь-заглушка «exit 1», systemctl show: failed): откат на 0.2.0.
	stage("0.4.0", priv)
	if out, err := apply(); err == nil {
		t.Fatalf("релиз с падающим агентом принят:\n%s", out)
	}
	// prev.deb — версия, под которой запущен сам бинарь (buildinfo.Version=0.1.0).
	if v := in(`cat /usr/share/tgproxy-ver`); v != "0.1.0" {
		t.Fatalf("нет отката после падения агента: версия %s", v)
	}
	if r := in(`cat /var/lib/tgproxy/updates/result.json; test ! -d /var/cache/tgproxy/packages/0.4.0 && echo failed-version-removed`); !strings.Contains(r, `"rolled_back":true`) || !strings.Contains(r, "failed-version-removed") {
		t.Fatalf("результат отката:\n%s", r)
	}

	// Чужая подпись: версия остаётся 0.2.0, request удалён, result.ok=false.
	_, other, _ := minisign.GenerateKey(rand.Reader)
	stage("0.3.0", other)
	if out, err := apply(); err == nil {
		t.Fatalf("подпись чужим ключом принята:\n%s", out)
	}
	if v := in(`cat /usr/share/tgproxy-ver`); v != "0.1.0" {
		t.Fatalf("версия изменилась при неверной подписи: %s", v)
	}
	if r := in(`cat /var/lib/tgproxy/updates/result.json; test ! -e /var/lib/tgproxy/updates/staged/request && echo no-request`); !strings.Contains(r, `"ok":false`) || !strings.Contains(r, "no-request") {
		t.Fatalf("результат:\n%s", r)
	}
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
