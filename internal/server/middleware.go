package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// isLoopbackHost reports whether hostport (as in an HTTP request's Host
// header, or an Origin/Referer URL's Host) refers to the local machine -
// "127.0.0.1", "::1", or "localhost", any port. The listener itself is
// already loopback-only by default (-addr defaults to 127.0.0.1), but that
// alone doesn't stop DNS rebinding: a browser tab on an attacker-controlled
// domain can be pointed at an A record that resolves to 127.0.0.1, and the
// browser will still send that domain as the Host header, not "127.0.0.1" -
// rejecting anything but a known loopback Host closes that gap regardless of
// what the request actually resolved to.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameOriginOrAbsent reports whether a state-changing request's Origin (or,
// if absent, Referer - some clients omit Origin on top-level navigations)
// points at a loopback host. No Origin/Referer at all (curl, scripts, or
// browsers that omit it for same-origin requests in some cases) is allowed
// through - this mirrors the trade-off every Origin-check CSRF defense makes
// for non-browser clients, and the Host check in hostOriginCheck is the
// primary defense regardless.
func sameOriginOrAbsent(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return true
	}
	u, err := url.Parse(src)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Host)
}

// hostOriginCheck defends bbtracker's unauthenticated local API against
// DNS-rebinding and cross-origin CSRF-style requests: it rejects any request
// whose Host isn't a recognized loopback address, and additionally rejects
// state-changing requests whose Origin/Referer isn't loopback either. There's
// no user auth (see CLAUDE.md's trust model for this local, single-user
// tool) - this is the alternative that doesn't require inventing a token
// the user would have to manage.
func hostOriginCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden: unrecognized Host", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !sameOriginOrAbsent(r) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// noCache forces browsers to revalidate the embedded frontend on every load
// instead of trusting cached Last-Modified/ETag values, which never change
// across rebuilds since embed.FS reports a fixed zero-value ModTime for
// every file - see the call site in routes().
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}
