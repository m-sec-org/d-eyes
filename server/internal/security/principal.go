package security

import "github.com/gin-gonic/gin"

// Principal represents the authenticated caller identity.
type Principal struct {
	User string
	Role string
}

type contextKey string

const principalKey contextKey = "principal"

// WithPrincipal stores the principal on the context.
func WithPrincipal(c *gin.Context, p Principal) {
	c.Set(string(principalKey), p)
}

// PrincipalFrom extracts principal from context (defaults to operator).
func PrincipalFrom(c *gin.Context) Principal {
	if value, ok := c.Get(string(principalKey)); ok {
		if p, ok := value.(Principal); ok {
			return p
		}
	}
	return Principal{User: "anonymous", Role: "operator"}
}
