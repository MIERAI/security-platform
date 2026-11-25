//go:build windows

package identity

// windowsPerms reports whether file modes are not Unix permissions (Windows: ACLs; the 0600 rule cannot be checked).
func windowsPerms() bool { return true }
