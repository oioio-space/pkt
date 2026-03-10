//go:build windows

// Package driver installs and manages the WinDivert kernel driver via SCM.
package driver

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WinDivert"

// Install extracts the .sys binary and installs the WinDivert driver via SCM.
// Idempotent — returns nil if the driver is already running.
func Install(sysData []byte) error {
	sysPath, err := extractSys(sysData)
	if err != nil {
		return fmt.Errorf("extract sys: %w", err)
	}
	return installService(sysPath)
}

// Uninstall stops and removes the WinDivert SCM service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	_, _ = s.Control(windows.SERVICE_CONTROL_STOP)
	return s.Delete()
}

// OpenDevice opens the WinDivert device and returns an overlapped-capable Windows handle.
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

func extractSys(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "windivert-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "WinDivert64.sys")
	return path, os.WriteFile(path, data, 0600)
}

func installService(sysPath string) error {
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

	s, err = m.CreateService(serviceName, sysPath, mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    mgr.StartManual,
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
	// Mirror the official WinDivert DLL: mark for deletion immediately after starting.
	// The SCM removes the service automatically once all handles are closed and the
	// driver stops — no manual cleanup needed.
	_ = s.Delete()
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
