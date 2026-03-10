//go:build windows

// Package driver installe et gère le driver kernel WinDivert via SCM.
package driver

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WinDivert"

// installConfig regroupe les options d'installation.
type installConfig struct {
	persistent bool   // true = SERVICE_AUTO_START + chemin stable + pas de Delete
	aclSDDL    string // SDDL DACL à appliquer sur le device après démarrage (vide = inchangé)
}

// InstallOption configure l'installation du driver.
type InstallOption func(*installConfig)

// WithPersistent installe le driver de façon permanente :
//   - Chemin stable : %SystemRoot%\System32\drivers\WinDivert64.sys
//   - StartType SERVICE_AUTO_START (démarre au boot)
//   - Le service n'est PAS marqué pour suppression automatique
//
// Sans cette option (défaut) : comportement temporaire identique à la DLL officielle
// (temp dir, StartManual, Delete immédiat après démarrage).
func WithPersistent() InstallOption {
	return func(c *installConfig) { c.persistent = true }
}

// WithACL applique un DACL personnalisé sur l'objet device WinDivert après démarrage.
// sddl est une chaîne SDDL décrivant le DACL, ex : "D:(A;;GA;;;AU)" pour
// autoriser Authenticated Users à ouvrir le device sans droits admin.
//
// Cette opération nécessite des privilèges admin lors de son application initiale.
// Une fois le DACL positionné, les processus non-admin peuvent ouvrir le device.
func WithACL(sddl string) InstallOption {
	return func(c *installConfig) { c.aclSDDL = sddl }
}

// WithUserAccess est un raccourci pour WithACL qui autorise tous les utilisateurs
// authentifiés (Authenticated Users, SID AU) à utiliser le driver WinDivert
// sans droits administrateur.
func WithUserAccess() InstallOption {
	return WithACL("D:(A;;GA;;;AU)")
}

// Install extrait le binaire .sys et installe le driver WinDivert via SCM.
// Sans options : comportement inchangé (temporaire, compatible avec l'existant).
func Install(sysData []byte, opts ...InstallOption) error {
	cfg := &installConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	sysPath, err := extractSys(sysData, cfg.persistent)
	if err != nil {
		return fmt.Errorf("extract sys: %w", err)
	}

	if err := installService(sysPath, cfg); err != nil {
		return err
	}

	if cfg.aclSDDL != "" {
		if err := applyDeviceACL(cfg.aclSDDL); err != nil {
			return fmt.Errorf("apply ACL: %w", err)
		}
	}
	return nil
}

// Uninstall arrête et supprime le service SCM WinDivert.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // non installé
	}
	defer s.Close()
	_, _ = s.Control(windows.SERVICE_CONTROL_STOP)
	return s.Delete()
}

// OpenDevice ouvre le device WinDivert et retourne un handle Windows compatible overlapped.
func OpenDevice() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`\\.\WinDivert`)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

// extractSys écrit le binaire .sys dans un chemin approprié.
// persistent=true → chemin stable dans %SystemRoot%\System32\drivers\.
// persistent=false → répertoire temporaire (comportement existant).
func extractSys(data []byte, persistent bool) (string, error) {
	if persistent {
		return extractSysStable(data)
	}
	dir, err := os.MkdirTemp("", "windivert-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "WinDivert64.sys")
	return path, os.WriteFile(path, data, 0600)
}

// extractSysStable écrit WinDivert64.sys dans %SystemRoot%\System32\drivers\.
// Si le fichier existe déjà (installation précédente), il est réutilisé tel quel.
func extractSysStable(data []byte) (string, error) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	path := filepath.Join(sysRoot, "System32", "drivers", "WinDivert64.sys")
	// Si déjà présent, ne pas écraser (le driver pourrait être en cours d'utilisation).
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return path, os.WriteFile(path, data, 0600)
}

func installService(sysPath string, cfg *installConfig) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		return startIfStopped(s)
	}

	startType := uint32(mgr.StartManual)
	if cfg.persistent {
		startType = uint32(mgr.StartAutomatic)
	}

	s, err = m.CreateService(serviceName, sysPath, mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    startType,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WinDivert Network Driver",
	})
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return err
	}

	if !cfg.persistent {
		// Comportement temporaire : marquer pour suppression automatique
		// quand le dernier handle WinDivert est fermé (comme la DLL officielle).
		_ = s.Delete()
	}
	return nil
}

func startIfStopped(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == windows.SERVICE_RUNNING {
		return nil
	}
	return s.Start()
}

// applyDeviceACL applique un DACL SDDL sur l'objet kernel device WinDivert.
// Nécessite des privilèges admin.
func applyDeviceACL(sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL %q: %w", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}

	h, err := OpenDevice()
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}
	defer windows.CloseHandle(h)

	return windows.SetSecurityInfo(
		h,
		windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
