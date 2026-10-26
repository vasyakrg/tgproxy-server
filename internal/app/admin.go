package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vasyakrg/tgproxy-server/internal/server/access"
	"github.com/vasyakrg/tgproxy-server/internal/store"
)

// AccessAddParams — параметры `tgproxy access add`.
type AccessAddParams struct {
	Name    string
	CIDRs   []string
	WithKey bool
	RPS     float64
}

// AccessAddResult — созданное правило и ключ в открытом виде (показывается
// один раз; в БД хранится только SHA-256).
type AccessAddResult struct {
	Rule store.AccessRule
	Key  string
}

// AccessAdd создаёт правило доступа в БД. Правило без сетей и без ключа
// отвергается (открытый relay к Bot API).
func AccessAdd(ctx context.Context, repo store.AccessRuleRepo, p AccessAddParams) (AccessAddResult, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return AccessAddResult{}, errors.New("access: --name is required")
	}
	if p.RPS < 0 {
		return AccessAddResult{}, errors.New("access: --rps must be >= 0")
	}
	rule := store.AccessRule{Name: name, RPS: p.RPS, Enabled: true}
	for _, c := range p.CIDRs {
		pfx, err := parsePrefix(c)
		if err != nil {
			return AccessAddResult{}, err
		}
		rule.CIDRs = append(rule.CIDRs, pfx)
	}
	var res AccessAddResult
	if p.WithKey {
		plain, hash, prefix, err := access.NewKey()
		if err != nil {
			return AccessAddResult{}, fmt.Errorf("access: generate key: %w", err)
		}
		rule.KeyHash, rule.KeyPrefix, res.Key = hash, prefix, plain
	}
	if err := rule.Validate(); err != nil {
		return AccessAddResult{}, err
	}
	created, err := repo.Create(ctx, rule)
	if err != nil {
		return AccessAddResult{}, fmt.Errorf("access: create rule: %w", err)
	}
	res.Rule = created
	return res, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("access: bad cidr %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// AccessDelete удаляет правило по id (id > 0) или по имени.
func AccessDelete(ctx context.Context, repo store.AccessRuleRepo, id int64, name string) (store.AccessRule, error) {
	if (id > 0) == (name != "") {
		return store.AccessRule{}, errors.New("access: specify exactly one of --id, --name")
	}
	var (
		r   store.AccessRule
		err error
	)
	if id > 0 {
		r, err = repo.Get(ctx, id)
	} else {
		r, err = repo.GetByName(ctx, name)
	}
	if err != nil {
		return store.AccessRule{}, fmt.Errorf("access: find rule: %w", err)
	}
	if err := repo.Delete(ctx, r.ID); err != nil {
		return store.AccessRule{}, fmt.Errorf("access: delete rule: %w", err)
	}
	return r, nil
}
