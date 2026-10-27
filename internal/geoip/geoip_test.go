package geoip

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// writeDB строит крошечную mmdb в формате DB-IP/GeoIP2 Country.
func writeDB(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-Country-Lite", IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	add := func(cidr, iso string) {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		rec := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)}}
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	add("8.8.8.0/24", "US")
	add("77.88.0.0/16", "ru")
	add("2001:4860::/32", "US")
	add("10.0.0.0/8", "ZZ") // приватный диапазон: игнорируется независимо от базы
	path := filepath.Join(t.TempDir(), "t.mmdb")
	f, err := os.Create(path) // #nosec G304 -- временный файл теста
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookup(t *testing.T) {
	db, err := Open(writeDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cases := map[string]string{
		"8.8.8.8":         "US",
		"77.88.1.1":       "RU",
		"::ffff:8.8.8.8":  "US",
		"2001:4860::8888": "US",
		"10.1.2.3":        "",
		"127.0.0.1":       "",
		"192.168.0.1":     "",
		"100.64.0.1":      "",
		"fe80::1":         "",
		"1.1.1.1":         "", // нет в тестовой базе
		"not-an-ip":       "",
	}
	for in, want := range cases {
		if got := db.LookupString(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
	if got := db.Lookup(netip.MustParseAddr("8.8.8.9")); got != "US" {
		t.Fatalf("got %q", got)
	}
}

func TestMissingAndNil(t *testing.T) {
	for _, p := range []string{"", filepath.Join(t.TempDir(), "none.mmdb")} {
		db, err := Open(p)
		if err != nil || db != nil {
			t.Fatalf("%q: %v %v", p, db, err)
		}
		if db.Available() || db.Lookup(netip.MustParseAddr("8.8.8.8")) != "" || db.Close() != nil {
			t.Fatal("nil db must be inert")
		}
	}
}

func TestOpenInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("want error for non-mmdb file")
	}
}

func TestFlag(t *testing.T) {
	if got := Flag("ru"); got != "🇷🇺" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"", "R", "RUS", "1A", "--"} {
		if Flag(bad) != "" {
			t.Fatalf("flag for %q", bad)
		}
	}
}
