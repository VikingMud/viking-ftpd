package authorization

// AccessSource provides access to the raw access tree data
type AccessSource interface {
	LoadAccessData() (map[string]interface{}, error)
}

// Permission represents the level of access granted
type Permission int

const (
	Revoked    Permission = -1
	Read       Permission = 1
	GrantRead  Permission = 2
	Write      Permission = 3
	GrantWrite Permission = 4
	GrantGrant Permission = 5
)

// isValid reports whether p is one of the defined permission levels. Note that
// 0 is not a valid level: LPC mappings cannot store a 0 value (assigning 0
// deletes the key), so an access entry is always Revoked (-1) or Read..GrantGrant.
func (p Permission) isValid() bool {
	return p == Revoked || (p >= Read && p <= GrantGrant)
}

// CanRead returns true if the permission allows reading
func (p Permission) CanRead() bool {
	return p >= Read
}

// CanWrite returns true if the permission allows writing
func (p Permission) CanWrite() bool {
	return p >= Write
}

// CanGrant returns true if the permission allows granting permissions
func (p Permission) CanGrant() bool {
	return p >= GrantGrant
}

// Group constants
const (
	GroupArchFull   = "Arch_full"
	GroupArchJunior = "Arch_junior"
	GroupArchDocs   = "Arch_docs"
	GroupArchQC     = "Arch_qc"
	GroupArchLaw    = "Arch_law"
	GroupArchWeb    = "Arch_web"
)

// AuthorizerConfig holds the configuration for creating a new Authorizer
type AuthorizerConfig struct {
	// DefaultPermission is used when no matching rule is found
	DefaultPermission Permission
}
