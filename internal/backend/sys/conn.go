package sys

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// defaultProbeURL is Ubuntu's connectivity endpoint. It answers HTTP 204 (No Content)
// with an empty body when reachability is unimpeded; a captive portal instead answers
// with a 3xx redirect to, or a 200 login page in place of, that empty response. Kept
// http:// (not https) on purpose so a portal can intercept it.
const defaultProbeURL = "http://connectivity-check.ubuntu.com/"

const probeTimeout = 5 * time.Second

// maxProbeBody caps how much of the response we inspect for portal detection.
const maxProbeBody = 4096

type connChecker struct {
	url    string
	client *http.Client
}

// NewConnChecker returns a ConnChecker that probes url (defaultProbeURL if empty). It
// uses a short timeout, no proxy (a proxy would mask a captive portal), and does not
// follow redirects (a redirect is itself the portal signal).
func NewConnChecker(url string) core.ConnChecker {
	if url == "" {
		url = defaultProbeURL
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: probeTimeout}).DialContext,
		TLSHandshakeTimeout:   probeTimeout,
		ResponseHeaderTimeout: probeTimeout,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &connChecker{url: url, client: client}
}

// Check probes the endpoint and maps the outcome onto an NM connectivity state:
//
//	ConnNone    - transport failure (no route, DNS failure, timeout).
//	ConnPortal  - a redirect, or a 2xx whose body looks like an injected login page.
//	ConnFull    - the expected clean 2xx with an empty/short non-HTML body.
//	ConnLimited - reachable, but the probe returned an unexpected status (4xx/5xx).
func (c *connChecker) Check(ctx context.Context) (core.Connectivity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return core.ConnUnknown, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return core.ConnNone, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return core.ConnPortal, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if looksLikePortal(body) {
			return core.ConnPortal, nil
		}
		return core.ConnFull, nil
	default:
		return core.ConnLimited, nil
	}
}

// looksLikePortal decides whether a 2xx body is a captive-portal login page rather than
// the endpoint's expected empty/short marker. The heuristic: HTML markup, or anything
// implausibly long, is a portal.
func looksLikePortal(body []byte) bool {
	t := strings.ToLower(strings.TrimSpace(string(body)))
	if t == "" {
		return false
	}
	if strings.Contains(t, "<html") || strings.Contains(t, "<!doctype") || strings.Contains(t, "<meta") {
		return true
	}
	return len(t) > 512
}
