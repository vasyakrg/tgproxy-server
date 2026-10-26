package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vasyakrg/tgproxy-server/internal/release/verify"
	"github.com/vasyakrg/tgproxy-server/internal/transport"
)

const (
	githubAPI  = "https://api.github.com"
	acceptJSON = "application/vnd.github+json"
)

// githubHosts — хосты, с которых разрешено качать (зеркало allowlist агента).
var githubHosts = map[string]bool{
	"github.com":                           true,
	"api.github.com":                       true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// GitHubHostAllowed — https-URL на хост GitHub без userinfo.
func GitHubHostAllowed(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && githubHosts[strings.ToLower(u.Hostname())]
}

// Getter выполняет GET; тело закрывает вызывающий.
type Getter func(ctx context.Context, rawURL, accept string) (*http.Response, error)

// GitHubSource читает GitHub Releases REST API. Один тип покрывает три канала,
// различающиеся только Getter'ом: напрямую, через HTTP-прокси (ProxySource,
// update.http_proxy), через агента (AgentEgressSource).
type GitHubSource struct {
	Repo     string                // owner/name
	APIBase  string                // по умолчанию https://api.github.com
	Get      Getter                // обязателен
	AllowURL func(raw string) bool // nil — без ограничений (только тесты)
}

// NewGitHubSource — прямой доступ или через HTTP-прокси (httpProxy != "").
func NewGitHubSource(repo, httpProxy string) (*GitHubSource, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if httpProxy != "" {
		pu, err := url.Parse(httpProxy)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
			return nil, fmt.Errorf("updater: некорректный http_proxy")
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	s := &GitHubSource{Repo: repo, AllowURL: GitHubHostAllowed}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 || !s.AllowURL(r.URL.String()) {
				return errors.New("updater: редирект вне allowlist")
			}
			return nil
		},
	}
	s.Get = func(ctx context.Context, rawURL, accept string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("User-Agent", "tgproxy-updater")
		return client.Do(req)
	}
	return s, nil
}

// AgentEgressSource — GitHub через GET /_agent/egress выбранного агента.
type AgentEgressSource struct{ *GitHubSource }

// NewAgentEgressSource строит источник, ходящий через агента по mTLS-каналу.
func NewAgentEgressSource(repo string, t transport.AgentTransport, agent transport.AgentRef) *AgentEgressSource {
	s := &GitHubSource{Repo: repo, AllowURL: GitHubHostAllowed}
	s.Get = func(ctx context.Context, rawURL, accept string) (*http.Response, error) {
		q := url.Values{"url": {rawURL}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/_agent/egress?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		return t.RoundTrip(ctx, agent, req)
	}
	return &AgentEgressSource{s}
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Latest возвращает последний опубликованный (не draft/prerelease) релиз.
func (s *GitHubSource) Latest(ctx context.Context) (Release, error) {
	base := s.APIBase
	if base == "" {
		base = githubAPI
	}
	resp, err := s.get(ctx, base+"/repos/"+s.Repo+"/releases/latest", acceptJSON)
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Release{}, ErrNoRelease
	case resp.StatusCode != http.StatusOK:
		return Release{}, fmt.Errorf("updater: GitHub API: HTTP %d", resp.StatusCode)
	}
	var gr ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetaSize)).Decode(&gr); err != nil {
		return Release{}, fmt.Errorf("updater: ответ GitHub API: %w", err)
	}
	if gr.Draft || gr.Prerelease {
		return Release{}, ErrNoRelease
	}
	ver := strings.TrimPrefix(gr.TagName, "v")
	if _, err := verify.ParseVersion(ver); err != nil {
		return Release{}, fmt.Errorf("updater: тег релиза %q: %w", gr.TagName, err)
	}
	rel := Release{Version: ver, Tag: gr.TagName, Notes: gr.Body, PublishedAt: gr.PublishedAt}
	for _, a := range gr.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, URL: a.URL, Size: a.Size})
	}
	return rel, nil
}

// Fetch скачивает артефакт релиза.
func (s *GitHubSource) Fetch(ctx context.Context, a Asset) (io.ReadCloser, error) {
	resp, err := s.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("updater: загрузка %s: HTTP %d", a.Name, resp.StatusCode)
	}
	return resp.Body, nil
}

func (s *GitHubSource) get(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	if s.AllowURL != nil && !s.AllowURL(rawURL) {
		return nil, fmt.Errorf("updater: URL вне allowlist")
	}
	return s.Get(ctx, rawURL, accept)
}
