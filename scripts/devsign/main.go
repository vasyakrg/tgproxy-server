// Command devsign — dev-инструмент подписи релиза minisign-ключом разработчика.
// Только для локального стенда (make dev-packages); в release-сборке не участвует.
//
//	devsign keygen --dir dev/data              создать minisign.key/minisign.pub, если их нет
//	devsign pubkey --dir dev/data              напечатать base64-строку публичного ключа
//	devsign sign --key K --out DIR deb...      DIR/<v>/{tgproxy_<v>_<arch>.deb,checksums.txt,checksums.txt.minisig}
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"aead.dev/minisign"
)

var debRe = regexp.MustCompile(`^tgproxy_([0-9][0-9A-Za-z.+~-]*)_([a-z0-9]+)\.deb$`)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "devsign:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается keygen|pubkey|sign")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := fs.String("dir", "dev/data", "каталог ключей")
	key := fs.String("key", "dev/data/minisign.key", "приватный ключ")
	outDir := fs.String("out", "dev/data/packages", "каталог результата")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		return keygen(*dir)
	case "pubkey":
		pub, err := readPub(*dir)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, pub)
		return err
	case "sign":
		return sign(*key, *outDir, fs.Args())
	}
	return fmt.Errorf("неизвестная команда %q", args[0])
}

func keygen(dir string) error {
	keyPath, pubPath := filepath.Join(dir, "minisign.key"), filepath.Join(dir, "minisign.pub")
	if _, err := os.Stat(keyPath); err == nil { // #nosec G703 -- путь из флага разработчика
		if _, err := os.Stat(pubPath); err == nil { // #nosec G703 -- то же
			return nil // идемпотентно
		}
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil { // #nosec G703 -- путь из флага разработчика
		return err
	}
	pt, _ := priv.MarshalText()                                            // без пароля: ключ только для dev и в .gitignore (dev/data/)
	if err := os.WriteFile(keyPath, append(pt, '\n'), 0o600); err != nil { // #nosec G703 -- путь из флага разработчика
		return err
	}
	pb, _ := pub.MarshalText()
	return os.WriteFile(pubPath, append(pb, '\n'), 0o644) // #nosec G306 G703 -- публичный ключ, путь из флага разработчика
}

func readPub(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "minisign.pub")) // #nosec G304 G703 -- путь из флага разработчика
	if err != nil {
		return "", err
	}
	var pk minisign.PublicKey
	if err := pk.UnmarshalText(bytes.TrimSpace(b)); err != nil {
		return "", err
	}
	return pk.String(), nil
}

func sign(keyPath, outDir string, debs []string) error {
	if len(debs) == 0 {
		return errors.New("не указан ни один deb")
	}
	kb, err := os.ReadFile(keyPath) // #nosec G304 G703 -- путь из флага разработчика
	if err != nil {
		return fmt.Errorf("ключ %s: %w", keyPath, err)
	}
	var priv minisign.PrivateKey
	if err := priv.UnmarshalText(bytes.TrimSpace(kb)); err != nil {
		return fmt.Errorf("ключ %s: %w", keyPath, err)
	}
	type rel struct{ lines []string }
	byVer := map[string]*rel{}
	for _, d := range debs {
		name := filepath.Base(d)
		m := debRe.FindStringSubmatch(name)
		if m == nil {
			return fmt.Errorf("%s: имя не похоже на tgproxy_<v>_<arch>.deb", name)
		}
		data, err := os.ReadFile(d) // #nosec G304 G703 -- путь из аргумента разработчика
		if err != nil {
			return err
		}
		vd := filepath.Join(outDir, m[1])
		if err := os.MkdirAll(vd, 0o755); err != nil { // #nosec G301 G703 -- dev-кэш, путь из аргументов разработчика
			return err
		}
		if err := os.WriteFile(filepath.Join(vd, name), data, 0o644); err != nil { // #nosec G306 G703 -- dev-инструмент, пути из аргументов
			return err
		}
		h := sha256.Sum256(data)
		if byVer[m[1]] == nil {
			byVer[m[1]] = &rel{}
		}
		byVer[m[1]].lines = append(byVer[m[1]].lines, hex.EncodeToString(h[:])+"  "+name)
	}
	for v, r := range byVer {
		sort.Strings(r.lines)
		sums := []byte(strings.Join(r.lines, "\n") + "\n")
		rd := minisign.NewReader(bytes.NewReader(sums))
		if _, err := io.Copy(io.Discard, rd); err != nil {
			return err
		}
		sig := rd.SignWithComments(priv, "timestamp:0 file:checksums.txt", "dev signature")
		vd := filepath.Join(outDir, v)
		if err := os.WriteFile(filepath.Join(vd, "checksums.txt"), sums, 0o644); err != nil { // #nosec G306 G703 -- dev-инструмент, пути из аргументов
			return err
		}
		if err := os.WriteFile(filepath.Join(vd, "checksums.txt.minisig"), sig, 0o644); err != nil { // #nosec G306 G703 -- dev-инструмент, пути из аргументов
			return err
		}
	}
	return nil
}
