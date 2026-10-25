package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func Test_getHostKeyCallback_SkipHostKeyCheck(t *testing.T) {
	cb, err := getHostKeyCallbackWithFile("/nonexistent/known_hosts", true)
	if err != nil {
		t.Fatalf("unexpected error when skipHostKeyCheck is true: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Host key callback should ignore any host key when skip is enabled
	if err := cb("example.com:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}, signer.PublicKey()); err != nil {
		t.Fatalf("expected nil error for InsecureIgnoreHostKey, got: %v", err)
	}
}

func Test_getHostKeyCallback_NonExistentFileCreated(t *testing.T) {
	tempDir := t.TempDir()
	knownHostsPath := filepath.Join(tempDir, "subdir", "known_hosts")

	cb, err := getHostKeyCallbackWithFile(knownHostsPath, false)
	if err != nil {
		t.Fatalf("unexpected error creating missing known_hosts: %v", err)
	}

	info, err := os.Stat(knownHostsPath)
	if err != nil {
		t.Fatalf("expected known_hosts file to be created: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected empty known_hosts file, got size: %d", info.Size())
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Because file is empty, unknown key error must be returned
	err = cb("example.com:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}, signer.PublicKey())
	if err == nil {
		t.Fatal("expected error for host not in known_hosts, got nil")
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *knownhosts.KeyError, got: %T: %v", err, err)
	}
}

func Test_getHostKeyCallback_Verification(t *testing.T) {
	tempDir := t.TempDir()
	knownHostsPath := filepath.Join(tempDir, "known_hosts")

	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key 1: %v", err)
	}
	signer1, err := ssh.NewSignerFromKey(priv1)
	if err != nil {
		t.Fatalf("failed to create signer 1: %v", err)
	}

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key 2: %v", err)
	}
	signer2, err := ssh.NewSignerFromKey(priv2)
	if err != nil {
		t.Fatalf("failed to create signer 2: %v", err)
	}

	// Write known_hosts entry for host 192.0.2.10
	line := knownhosts.Line([]string{"192.0.2.10"}, signer1.PublicKey())
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	cb, err := getHostKeyCallbackWithFile(knownHostsPath, false)
	if err != nil {
		t.Fatalf("failed to create callback: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

	// Matching host and key should pass
	if err := cb("192.0.2.10:22", addr, signer1.PublicKey()); err != nil {
		t.Fatalf("expected matching key to pass, got: %v", err)
	}

	// Mismatched key for known host should fail with KeyError containing wanted keys
	err = cb("192.0.2.10:22", addr, signer2.PublicKey())
	if err == nil {
		t.Fatal("expected error for mismatched key, got nil")
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *knownhosts.KeyError, got: %T: %v", err, err)
	}
	if len(keyErr.Want) == 0 {
		t.Fatalf("expected keyErr.Want to have entries for mismatched key")
	}

	// Unknown host should fail with KeyError where Want is empty
	err = cb("192.0.2.99:22", &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 22}, signer1.PublicKey())
	if err == nil {
		t.Fatal("expected error for unknown host, got nil")
	}
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *knownhosts.KeyError, got: %T: %v", err, err)
	}
}
