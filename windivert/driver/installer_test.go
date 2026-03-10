//go:build windows

package driver

import "testing"

// TestInstallOptionsCompile vérifie que les options d'installation compilent.
func TestInstallOptionsCompile(t *testing.T) {
	opts := []InstallOption{
		WithPersistent(),
		WithUserAccess(),
		WithACL("D:(A;;GA;;;WD)"),
	}
	_ = opts
}
