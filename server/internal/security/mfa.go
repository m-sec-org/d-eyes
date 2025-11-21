package security

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

// MFAStore keeps runtime MFA configuration and secrets.
type MFAStore struct {
	enabled  bool
	header   string
	required map[string]struct{}

	mu      sync.RWMutex
	secrets map[string]string
}

// NewMFAStore builds a store from config (may be nil when disabled).
func NewMFAStore(cfg config.MFAConfig) *MFAStore {
	store := &MFAStore{}
	store.configure(cfg)
	return store
}

func (s *MFAStore) configure(cfg config.MFAConfig) {
	s.enabled = cfg.Enabled
	header := strings.TrimSpace(cfg.Header)
	if header == "" {
		header = "X-MFA-Code"
	}
	s.header = header
	s.required = make(map[string]struct{}, len(cfg.RequiredRoles))
	for _, role := range cfg.RequiredRoles {
		if trimmed := strings.ToLower(strings.TrimSpace(role)); trimmed != "" {
			s.required[trimmed] = struct{}{}
		}
	}
	s.UpdateSecrets(cfg.Secrets)
}

// Enabled returns true if MFA is enforced for any role.
func (s *MFAStore) Enabled() bool {
	return s != nil && s.enabled && len(s.required) > 0
}

// Middleware enforces MFA using the current store state.
func (s *MFAStore) Middleware() gin.HandlerFunc {
	if s == nil || !s.Enabled() {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	return func(c *gin.Context) {
		principal := PrincipalFrom(c)
		if !s.roleRequiresMFA(principal.Role) {
			c.Next()
			return
		}
		code := strings.TrimSpace(c.GetHeader(s.header))
		if code == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "missing mfa code"})
			c.Abort()
			return
		}
		expected := s.lookupSecret(principal.User, principal.Role)
		if expected == "" || subtle.ConstantTimeCompare([]byte(code), []byte(expected)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid mfa code"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Header returns the configured MFA header name.
func (s *MFAStore) Header() string {
	if s == nil {
		return ""
	}
	return s.header
}

// UpdateSecrets replaces the in-memory secret map.
func (s *MFAStore) UpdateSecrets(secrets map[string]string) {
	if s == nil {
		return
	}
	normalized := make(map[string]string, len(secrets))
	for k, v := range secrets {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if key != "" && val != "" {
			normalized[key] = val
		}
	}
	s.mu.Lock()
	s.secrets = normalized
	s.mu.Unlock()
}

// MergeSecrets merges additional secrets without removing existing ones.
func (s *MFAStore) MergeSecrets(secrets map[string]string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.secrets == nil {
		s.secrets = make(map[string]string)
	}
	for k, v := range secrets {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if key != "" && val != "" {
			s.secrets[key] = val
		}
	}
	s.mu.Unlock()
}

// Secrets returns a copy of current secrets (redacted values left intact for ops usage).
func (s *MFAStore) Secrets() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	copyMap := make(map[string]string, len(s.secrets))
	for k, v := range s.secrets {
		copyMap[k] = v
	}
	return copyMap
}

func (s *MFAStore) roleRequiresMFA(role string) bool {
	if s == nil || len(s.required) == 0 {
		return false
	}
	role = strings.ToLower(strings.TrimSpace(role))
	_, ok := s.required[role]
	return ok
}

func (s *MFAStore) lookupSecret(user, role string) string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	userKey := strings.ToLower(strings.TrimSpace(user))
	if val, ok := s.secrets[userKey]; ok && val != "" {
		return val
	}
	roleKey := "role:" + strings.ToLower(strings.TrimSpace(role))
	if val, ok := s.secrets[roleKey]; ok && val != "" {
		return val
	}
	if val, ok := s.secrets["default"]; ok && val != "" {
		return val
	}
	return ""
}
