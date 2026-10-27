package tgapi

import (
	"net/netip"
	"testing"
)

func inPrefixes(a netip.Addr) bool {
	for _, p := range TelegramPrefixes() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func TestDCAddrs_KnownDCsHaveIPv4(t *testing.T) {
	for _, dc := range []int{1, 2, 3, 4, 5, -1, -2, -3, -4, -5} {
		if !KnownDC(dc) {
			t.Errorf("KnownDC(%d) = false", dc)
		}
		if len(DCAddrs(dc, false)) == 0 {
			t.Errorf("DC %d: нет IPv4", dc)
		}
	}
}

func TestDCAddrs_MediaEqualsBase(t *testing.T) {
	for _, dc := range KnownDCs() {
		a, b := DCAddrs(dc, false), DCAddrs(-dc, false)
		if len(a) != len(b) {
			t.Fatalf("DC %d: media отличается", dc)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("DC %d: %v != %v", dc, a[i], b[i])
			}
		}
	}
}

func TestDCAddrs_AllInPrefixesPort443(t *testing.T) {
	for _, dc := range KnownDCs() {
		for _, v6 := range []bool{false, true} {
			as := DCAddrs(dc, v6)
			if len(as) == 0 {
				t.Errorf("DC %d v6=%v: пусто", dc, v6)
			}
			for _, ap := range as {
				if ap.Port() != 443 {
					t.Errorf("DC %d: порт %d", dc, ap.Port())
				}
				if ap.Addr().Is6() != v6 {
					t.Errorf("DC %d: семейство %v, v6=%v", dc, ap, v6)
				}
				if !inPrefixes(ap.Addr()) {
					t.Errorf("DC %d: %v вне TelegramPrefixes", dc, ap)
				}
			}
		}
	}
}

func TestDCAddrs_Unknown(t *testing.T) {
	for _, dc := range []int{0, 6, 100, -6, 999} {
		if KnownDC(dc) {
			t.Errorf("KnownDC(%d) = true", dc)
		}
		if got := DCAddrs(dc, false); len(got) != 0 {
			t.Errorf("DCAddrs(%d) = %v", dc, got)
		}
		if got := DCAddrs(dc, true); len(got) != 0 {
			t.Errorf("DCAddrs(%d, v6) = %v", dc, got)
		}
	}
}

func TestDCAddrs_ReturnsCopy(t *testing.T) {
	a := DCAddrs(2, false)
	orig := a[0]
	a[0] = netip.MustParseAddrPort("127.0.0.1:1")
	if DCAddrs(2, false)[0] != orig {
		t.Fatal("таблица испорчена вызывающим")
	}
	p := TelegramPrefixes()
	p0 := p[0]
	p[0] = netip.MustParsePrefix("10.0.0.0/8")
	if TelegramPrefixes()[0] != p0 {
		t.Fatal("префиксы испорчены вызывающим")
	}
	d := KnownDCs()
	d0 := d[0]
	d[0] = 999
	if KnownDCs()[0] != d0 {
		t.Fatal("KnownDCs испорчен вызывающим")
	}
}
