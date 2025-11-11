package rbac

import "strings"

// Policy describes role permissions.
type Policy struct {
	Role        string
	Permissions []string
}

// Enforcer stores policy mapping for quick checks.
type Enforcer struct {
	policies map[string]map[string]struct{}
}

// New creates a new Enforcer.
func New(policies []Policy) *Enforcer {
	m := make(map[string]map[string]struct{})
	for _, policy := range policies {
		role := strings.ToLower(strings.TrimSpace(policy.Role))
		if role == "" {
			continue
		}
		if _, ok := m[role]; !ok {
			m[role] = make(map[string]struct{})
		}
		for _, perm := range policy.Permissions {
			p := normalizePermission(perm)
			if p != "" {
				m[role][p] = struct{}{}
			}
		}
	}
	return &Enforcer{policies: m}
}

// Enforce checks whether the role has permission.
func (e *Enforcer) Enforce(role, permission string) bool {
	if e == nil {
		return true
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = "operator"
	}
	perm := normalizePermission(permission)
	if perm == "" {
		return true
	}
	allowed, ok := e.policies[role]
	if !ok {
		return false
	}
	if _, ok := allowed["*"]; ok {
		return true
	}
	_, ok = allowed[perm]
	return ok
}

// Policies returns the configured policies.
func (e *Enforcer) Policies() []Policy {
	if e == nil {
		return nil
	}
	result := make([]Policy, 0, len(e.policies))
	for role, perms := range e.policies {
		policy := Policy{Role: role}
		for perm := range perms {
			policy.Permissions = append(policy.Permissions, perm)
		}
		result = append(result, policy)
	}
	return result
}

func normalizePermission(permission string) string {
	return strings.ToLower(strings.TrimSpace(permission))
}
