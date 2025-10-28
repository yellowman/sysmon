package config

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"sysmon-web/internal/models"
)

// Service handles configuration management
type Service struct {
	configPath string
	backupDir  string
	auditLog   string
	mu         sync.RWMutex
}

// NewService creates a new config service
func NewService(configPath, backupDir, auditLog string) *Service {
	// Ensure backup directory exists
	os.MkdirAll(backupDir, 0755)

	return &Service{
		configPath: configPath,
		backupDir:  backupDir,
		auditLog:   auditLog,
	}
}

// GetConfig returns the current config with version
func (s *Service) GetConfig() (*models.ConfigSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Read file
	content, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Get file modification time
	stat, err := os.Stat(s.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config: %w", err)
	}

	// Calculate version (SHA256 hash)
	version := fmt.Sprintf("%x", sha256.Sum256(content))

	// Parse config
	config, err := Parse(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &models.ConfigSnapshot{
		Version: version,
		Config:  *config,
		ModTime: stat.ModTime(),
	}, nil
}

// UpdateConfig updates the config with optimistic locking
func (s *Service) UpdateConfig(update *models.ConfigUpdate, user, ip string) (*models.ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Get current version
	current, err := s.getCurrentVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}

	// 2. Check version match (optimistic locking)
	if update.Version != current {
		currentSnapshot, err := s.getConfigUnlocked()
		if err != nil {
			return nil, fmt.Errorf("version conflict detected but unable to read current config: %w", err)
		}
		return nil, &models.VersionConflictError{
			Expected: update.Version,
			Actual:   current,
			Current:  currentSnapshot,
			Message:  "Config was modified by another user. Please review changes and try again.",
		}
	}

	// 3. Validate config
	if err := Validate(&update.Config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// 4. Generate new config content
	newContent, err := Generate(&update.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate config: %w", err)
	}

	// 5. Backup current config
	if err := s.backupConfig(update.Comment); err != nil {
		return nil, fmt.Errorf("backup failed: %w", err)
	}

	// 6. Write new config atomically (temp + rename)
	tempPath := s.configPath + ".tmp"
	if err := os.WriteFile(tempPath, []byte(newContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempPath, s.configPath); err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("failed to rename temp file: %w", err)
	}

	// 7. Log audit entry
	s.logAudit("config_update", user, ip, update.Comment)

	// 8. Signal sysmon to reload (SIGHUP)
	if err := s.reloadSysmon(); err != nil {
		// Log but don't fail - config was updated successfully
		s.logAudit("reload_failed", user, ip, err.Error())
	}

	// 9. Return new snapshot
	return s.getConfigUnlocked()
}

// GetRawConfig returns the raw config file content
func (s *Service) GetRawConfig() (string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	content, err := os.ReadFile(s.configPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read config: %w", err)
	}

	version := fmt.Sprintf("%x", sha256.Sum256(content))
	return string(content), version, nil
}

// UpdateRawConfig updates the raw config file
func (s *Service) UpdateRawConfig(content, version, comment, user, ip string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check version
	current, err := s.getCurrentVersion()
	if err != nil {
		return "", err
	}

	if version != current {
		return "", &models.VersionConflictError{
			Expected: version,
			Actual:   current,
			Message:  "Config was modified by another user",
		}
	}

	// Parse to validate
	_, err = Parse([]byte(content))
	if err != nil {
		return "", fmt.Errorf("config validation failed: %w", err)
	}

	// Backup
	if err := s.backupConfig(comment); err != nil {
		return "", err
	}

	// Write
	tempPath := s.configPath + ".tmp"
	if err := os.WriteFile(tempPath, []byte(content), 0644); err != nil {
		return "", err
	}

	if err := os.Rename(tempPath, s.configPath); err != nil {
		os.Remove(tempPath)
		return "", err
	}

	s.logAudit("raw_config_update", user, ip, comment)

	// Attempt to reload sysmon daemon - log but don't fail if reload fails
	// Config was successfully updated, reload is a separate operation
	if err := s.reloadSysmon(); err != nil {
		s.logAudit("reload_failed", user, ip, fmt.Sprintf("Config updated but reload failed: %v", err))
		// Note: We still return success since config was updated
	}

	newVersion := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	return newVersion, nil
}

// ListBackups returns available backups
func (s *Service) ListBackups() ([]models.Backup, error) {
	entries, err := os.ReadDir(s.backupDir)
	if err != nil {
		return nil, err
	}

	backups := []models.Backup{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".conf" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		backups = append(backups, models.Backup{
			Timestamp: info.ModTime(),
			Filename:  entry.Name(),
			Size:      info.Size(),
		})
	}

	return backups, nil
}

// RestoreBackup restores a backup
func (s *Service) RestoreBackup(filename, user, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	backupPath := filepath.Join(s.backupDir, filename)

	// Read backup
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Validate
	_, err = Parse(content)
	if err != nil {
		return fmt.Errorf("backup is invalid: %w", err)
	}

	// Backup current before restoring
	if err := s.backupConfig("pre-restore backup"); err != nil {
		return err
	}

	// Restore
	if err := os.WriteFile(s.configPath, content, 0644); err != nil {
		return err
	}

	s.logAudit("restore_backup", user, ip, filename)

	// Attempt to reload sysmon daemon - log but don't fail if reload fails
	// Backup was successfully restored, reload is a separate operation
	if err := s.reloadSysmon(); err != nil {
		s.logAudit("reload_failed", user, ip, fmt.Sprintf("Backup restored but reload failed: %v", err))
		// Note: We still return success since backup was restored
	}

	return nil
}

// ValidateConfig validates a config without saving
func (s *Service) ValidateConfig(cfg *models.Config) error {
	return Validate(cfg)
}

// ReloadSysmon sends SIGHUP to reload the sysmon daemon
func (s *Service) ReloadSysmon() error {
	return s.reloadSysmon()
}

// getCurrentVersion gets the version without parsing
func (s *Service) getCurrentVersion() (string, error) {
	content, err := os.ReadFile(s.configPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// getConfigUnlocked reads config without locking (must be called with lock held)
func (s *Service) getConfigUnlocked() (*models.ConfigSnapshot, error) {
	content, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(s.configPath)
	if err != nil {
		return nil, err
	}

	version := fmt.Sprintf("%x", sha256.Sum256(content))
	config, err := Parse(content)
	if err != nil {
		return nil, err
	}

	return &models.ConfigSnapshot{
		Version: version,
		Config:  *config,
		ModTime: stat.ModTime(),
	}, nil
}

// backupConfig creates a backup of the current config
func (s *Service) backupConfig(comment string) error {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(s.backupDir, fmt.Sprintf("sysmon-%s.conf", timestamp))

	src, err := os.Open(s.configPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		// Explicitly close src since defer hasn't registered for dst yet
		src.Close()
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

// logAudit logs an audit entry
func (s *Service) logAudit(action, user, ip, details string) {
	f, err := os.OpenFile(s.auditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("%s | %s | %s | %s | %s\n", timestamp, action, user, ip, details)
	f.WriteString(entry)
}

// reloadSysmon sends SIGHUP to sysmon daemon
func (s *Service) reloadSysmon() error {
	// Read PID from /var/run/sysmond.pid
	pidContent, err := os.ReadFile("/var/run/sysmond.pid")
	if err != nil {
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	var pid int
	if _, err := fmt.Sscanf(string(pidContent), "%d", &pid); err != nil {
		return fmt.Errorf("failed to parse PID from file: %w", err)
	}

	if pid <= 0 || pid > 1<<22 { // Max reasonable PID on modern Linux
		return fmt.Errorf("invalid PID value: %d", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGHUP
	return process.Signal(syscall.SIGHUP)
}
