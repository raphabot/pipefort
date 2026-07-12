package vcs

import "net/http"

// Option customizes a GitHub or GitLab client at construction time. The two
// tuning knobs — a base-URL override and a custom *http.Client — are what
// tests (in this module and, via the vcstest helpers, in dependent modules)
// need to point a client at an httptest server. Production callers never pass
// options; the zero configuration talks to the real APIs.
type Option func(*clientOptions)

type clientOptions struct {
	baseURL    string
	httpClient *http.Client
}

func newClientOptions(opts []Option) clientOptions {
	var c clientOptions
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithBaseURL overrides the API base URL. For GitHub this replaces
// https://api.github.com; for GitLab it replaces https://{host}/api/v4.
func WithBaseURL(u string) Option {
	return func(o *clientOptions) { o.baseURL = u }
}

// WithHTTPClient supplies the *http.Client used for all requests.
func WithHTTPClient(h *http.Client) Option {
	return func(o *clientOptions) { o.httpClient = h }
}
