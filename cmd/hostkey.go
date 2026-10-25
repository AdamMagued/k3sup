package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// getHostKeyCallback returns an ssh.HostKeyCallback.
// If skipHostKeyCheck is true, it returns ssh.InsecureIgnoreHostKey().
// Otherwise, it returns a callback backed by the standard ~/.ssh/known_hosts file.
func getHostKeyCallback(skipHostKeyCheck bool) (ssh.HostKeyCallback, error) {
	return getHostKeyCallbackWithFile(expandPath("~/.ssh/known_hosts"), skipHostKeyCheck)
}

// getHostKeyCallbackWithFile returns an ssh.HostKeyCallback using a specific known_hosts file path.
func getHostKeyCallbackWithFile(knownHostsPath string, skipHostKeyCheck bool) (ssh.HostKeyCallback, error) {
	if skipHostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		dir := filepath.Dir(knownHostsPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("unable to create ssh directory %q: %w", dir, err)
		}
		f, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("unable to create known_hosts file %q: %w", knownHostsPath, err)
		}
		f.Close()
	}

	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read known_hosts file %q: %w", knownHostsPath, err)
	}

	return callback, nil
}
