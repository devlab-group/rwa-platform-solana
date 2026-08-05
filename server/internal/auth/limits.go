package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxRequestBody bounds every request body to maxBytes via
// http.MaxBytesReader. An unbounded request body is a trivial
// memory-exhaustion vector against endpoints that buffer
// the whole request, like POST /api/v1/profile/validate or
// .../assets/records). A body that exceeds the limit fails with 413 the
// first time a handler actually reads past maxBytes (http.MaxBytesReader's
// own behavior — this middleware only installs the reader; it does not
// eagerly read the body itself, so a route that never reads its body pays
// nothing extra). maxBytes<=0 disables the limit entirely.
func MaxRequestBody(maxBytes int64) gin.HandlerFunc {
	if maxBytes <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// ContentSecurityPolicy is the CSP for API/JSON responses
// (internal/api.NewRouter): no unsafe-inline/unsafe-eval needed anywhere,
// and connect-src 'self' is correct as-is even though the app talks to
// wallets/RPC endpoints — none of that happens through an API JSON
// response.
//
// This used to also cover the SPA shell response, widened per-deployment
// with the Solana public RPC origin (connectSrcOrigins). A later change
// removed that: the server no longer knows the browser's Solana RPC
// endpoint at all (it is a build-time-only value baked into the SPA), and
// the SPA's own build-time <meta> CSP tag now authors every fetch directive
// itself — see SPAContentSecurityPolicy below for the (now much narrower)
// policy the server still sends alongside it.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"

// SPAContentSecurityPolicy is the CSP for the SPA shell response
// (internal/webui's NoRoute handler): the build-time <meta>
// CSP tag now authors every fetch directive (default-src/connect-src/
// script-src/style-src/img-src/font-src/...), since the server no longer
// knows the browser's Solana RPC origin to widen connect-src with. Browsers
// INTERSECT a meta CSP with the response header, so the header must NOT
// also emit those fetch directives — doing so (e.g. this response's own
// former default-src 'self') would silently re-cap connect-src back down
// regardless of what the meta tag grants. What's left is only the
// directives a <meta> CSP tag is documented not to honor:
// frame-ancestors, plus base-uri/form-action (kept here rather than left to
// the meta tag, matching the decision's explicit list).
const SPAContentSecurityPolicy = "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// setSecurityHeaders applies the baseline security response headers common
// to every response, with csp as the caller-selected Content-Security-Policy
// (ContentSecurityPolicy for API/JSON responses, SPAContentSecurityPolicy
// for the SPA shell — see SetSecurityHeaders/SetSPASecurityHeaders below).
func setSecurityHeaders(h http.Header, csp string) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY") // redundant with the CSP's frame-ancestors 'none' for browsers that honor both; kept for older UAs that only understand this header
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", csp)
	// Meaningless over plain HTTP (no-op), harmless to always send — takes
	// effect the moment a deployment terminates TLS in front of this
	// server, without needing a code change then.
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("X-XSS-Protection", "0") // deprecated legacy header; explicitly disabled per modern guidance, not left unset/ambiguous
}

// SetSecurityHeaders applies the baseline security response headers plus
// the full API/JSON ContentSecurityPolicy to h. For internal/api.NewRouter's
// JSON responses.
func SetSecurityHeaders(h http.Header) { setSecurityHeaders(h, ContentSecurityPolicy) }

// SetSPASecurityHeaders applies the baseline security response headers plus
// the reduced SPAContentSecurityPolicy to h. For internal/webui's SPA shell
// response, which relies on its own build-time <meta> CSP tag for every
// fetch directive (see SPAContentSecurityPolicy's doc comment).
func SetSPASecurityHeaders(h http.Header) { setSecurityHeaders(h, SPAContentSecurityPolicy) }

// SecurityHeaders is SetSecurityHeaders as Gin middleware, for the API
// router's chain (internal/api.NewRouter).
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		SetSecurityHeaders(c.Writer.Header())
		c.Next()
	}
}
