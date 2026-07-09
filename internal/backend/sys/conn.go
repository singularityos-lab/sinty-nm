package sys

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// defaultProbeURL is Ubuntu's connectivity endpoint. Its contract: HTTP 204 (No Content)
// with an empty body when reachability is unimpeded. A captive portal instead answers
// with a 3xx redirect or any other substituted response (typically a 200 login page).
// Kept http:// (not https) on purpose so a portal can intercept it.
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
//	ConnPortal  - a redirect, or any 2xx other than the contracted 204-empty reply
//	              (a portal substituting its own page for the probe response).
//	ConnFull    - exactly the endpoint's contract: 204 with an empty body.
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
	case resp.StatusCode == http.StatusNoContent && len(body) == 0:
		return core.ConnFull, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return core.ConnPortal, nil
	default:
		return core.ConnLimited, nil
	}
}
