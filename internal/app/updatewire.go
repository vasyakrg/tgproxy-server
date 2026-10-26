package app

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/buildinfo"
	"github.com/vasyakrg/tgproxy-server/internal/config"
	"github.com/vasyakrg/tgproxy-server/internal/redact"
	"github.com/vasyakrg/tgproxy-server/internal/release"
	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/server/updater"
	"github.com/vasyakrg/tgproxy-server/internal/server/web/api"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	uploadDirName   = "upload"
	resultFileName  = "result.json"
	firstCheckDelay = 15 * time.Second
	checkTimeout    = 2 * time.Minute
)

// updateState — самообновление сервера (§12): Updater и сервис для экрана «Система».
// up == nil — update.enabled=false.
type updateState struct {
	up       *updater.Updater
	svc      *api.SystemService
	interval time.Duration
}

// agentRefs отдаёт актуальную ссылку на агента по id (реестр агентов).
type agentRefs interface {
	Ref(id string) (transport.AgentRef, bool)
}

// lazyAgentSource — GitHub через egress агента; агент ищется при каждом запросе, поэтому
// источник работает и если агент появился после старта сервера.
type lazyAgentSource struct {
	repo string
	id   string
	refs agentRefs
	tr   transport.AgentTransport
}

func (l lazyAgentSource) inner() (updater.Source, error) {
	ref, ok := l.refs.Ref(l.id)
	if !ok {
		return nil, fmt.Errorf("агент %q для загрузки обновлений не найден", l.id)
	}
	return updater.NewAgentEgressSource(l.repo, l.tr, ref), nil
}

func (l lazyAgentSource) Latest(ctx context.Context) (updater.Release, error) {
	s, err := l.inner()
	if err != nil {
		return updater.Release{}, err
	}
	return s.Latest(ctx)
}

func (l lazyAgentSource) Fetch(ctx context.Context, a updater.Asset) (io.ReadCloser, error) {
	s, err := l.inner()
	if err != nil {
		return nil, err
	}
	return s.Fetch(ctx, a)
}

func updatePubKeys(u config.UpdateConfig) ([]verify.PublicKey, error) {
	if len(u.PubKeys) > 0 {
		return verify.ParsePublicKeys(u.PubKeys)
	}
	return release.EmbeddedPubKeys()
}

// updateSource строит источник из update.source и его подпись для экрана.
func (s *Server) updateSource(u config.UpdateConfig, uploadDir, arch string) (updater.Source, api.SourceInfo, error) {
	switch u.Source {
	case config.UpdateSourceProxy:
		src, err := updater.NewGitHubSource(u.Repo, u.HTTPProxy)
		host := ""
		if pu, perr := url.Parse(u.HTTPProxy); perr == nil {
			host = pu.Host
		}
		return src, api.SourceInfo{Kind: u.Source, Detail: host}, err
	case config.UpdateSourceAgent:
		return lazyAgentSource{repo: u.Repo, id: u.ViaAgent, refs: s.reg, tr: s.tr},
			api.SourceInfo{Kind: u.Source, Detail: u.ViaAgent}, nil
	case config.UpdateSourceUpload:
		return updater.UploadSource{Dir: uploadDir, Arch: arch}, api.SourceInfo{Kind: u.Source}, nil
	default:
		src, err := updater.NewGitHubSource(u.Repo, "")
		return src, api.SourceInfo{Kind: config.UpdateSourceGitHub, Detail: u.Repo}, err
	}
}

// wireUpdate собирает Updater и сервис «Система». При update.enabled=false сервис работает
// без Updater (экран покажет «самообновление выключено»).
func (s *Server) wireUpdate(cfg *config.ServerConfig) (*updateState, error) {
	u := cfg.Update
	arch := runtime.GOARCH
	uploadDir := filepath.Join(u.StagingDir, uploadDirName)
	sc := api.SystemConfig{
		Version: buildinfo.Version, UploadDir: uploadDir, Arch: arch, MinVersion: u.MinVersion,
		ResultPath: filepath.Join(u.StagingDir, resultFileName), Audit: s.st.Audit(), Logger: s.logger,
		Source: api.SourceInfo{Kind: u.Source},
	}
	st := &updateState{interval: u.CheckInterval}
	if !u.Enabled {
		st.svc = api.NewSystemService(sc)
		return st, nil
	}
	keys, err := updatePubKeys(u)
	if err != nil {
		return nil, fmt.Errorf("app: update pubkeys: %w", redact.Error(err))
	}
	src, info, err := s.updateSource(u, uploadDir, arch)
	if err != nil {
		return nil, fmt.Errorf("app: update source: %w", redact.Error(err))
	}
	sw := &api.SourceSwitch{Base: src, Upload: updater.UploadSource{Dir: uploadDir, Arch: arch}}
	up, err := updater.New(updater.Config{
		Source: sw, SourceName: info.Kind, StagingDir: u.StagingDir, DownloadsDir: u.Downloads(), Arch: arch, PubKeys: keys,
		MinVersion: u.MinVersion, Current: buildinfo.Version, Logger: s.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("app: updater: %w", redact.Error(err))
	}
	sc.Updater, sc.Switch, sc.Source, sc.PubKeys = up, sw, info, keys
	st.up, st.svc = up, api.NewSystemService(sc)
	return st, nil
}

// run периодически проверяет обновления (update.check_interval) до отмены ctx.
func (st *updateState) run(ctx context.Context, s *Server) {
	if st == nil || st.up == nil || st.interval <= 0 {
		return
	}
	check := func() {
		cctx, cancel := context.WithTimeout(ctx, checkTimeout)
		defer cancel()
		if _, err := st.svc.Refresh(cctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("update check failed", "error", redact.Error(err))
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(firstCheckDelay):
	}
	check()
	t := time.NewTicker(st.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
