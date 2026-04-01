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
	persistent bool // true = SERVICE_AUTO_START + chemin stable + pas de Delete
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
//
// Note : WinDivert requiert toujours des droits administrateur pour ouvrir le device.
// Son DACL (SDDL_DEVOBJ_SYS_ALL_ADM_ALL) est fixé à la création du device object par le
// driver WDF et ne peut pas être modifié depuis l'espace utilisateur.
func WithPersistent() InstallOption {
	return func(c *installConfig) { c.persistent = true }
}

// Install extrait le binaire .sys et installe le driver WinDivert via SCM.
// Sans options : comportement temporaire identique à la DLL officielle.
func Install(sysData []byte, opts ...InstallOption) error {
	cfg := &installConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	sysPath, err := extractSys(sysData, cfg.persistent)
	if err != nil {
		return fmt.Errorf("extract sys: %w", err)
	}

	return installService(sysPath, cfg)
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

func extractSysStable(data []byte) (string, error) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	path := filepath.Join(sysRoot, "System32", "drivers", "WinDivert64.sys")
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
