package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

const nodeFixtureListen = "127.0.0.1:19443"

type nodeFixtureMetadata struct {
	HubURL      string    `json:"hub_url"`
	NodeID      string    `json:"node_id"`
	Role        node.Role `json:"role"`
	VLESSPort   int       `json:"vless_port"`
	SSHPort     int       `json:"ssh_port"`
	PairingCode string    `json:"pairing_code"`
	CAPath      string    `json:"ca_path"`
}

// TestNodeHubFixture is a disposable-VM fixture, not a normal unit test. It
// runs the actual Web handler with persistent SQLite and a private TLS CA. The
// env guard keeps ordinary go test invocations from opening a listener.
func TestNodeHubFixture(t *testing.T) {
	dir := os.Getenv("MESHMUX_NODE_HUB_FIXTURE_DIR")
	if dir == "" {
		t.Skip("MESHMUX_NODE_HUB_FIXTURE_DIR is not set: set it (with MESHMUX_NODE_HUB_FIXTURE_ROLE=edge or out) to run the isolated Node VM Hub fixture")
	}
	role := node.Role(os.Getenv("MESHMUX_NODE_HUB_FIXTURE_ROLE"))
	if role != node.RoleEdge && role != node.RoleOut {
		t.Fatalf("fixture role must be edge or out")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareFixtureDir(dir); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	caKeyPath := filepath.Join(dir, "ca.key")
	stateDir := filepath.Join(dir, "state")
	metadataPath := filepath.Join(dir, "node-fixture.json")
	readyPath := filepath.Join(dir, "fixture-ready")
	eventsPath := filepath.Join(dir, "events.jsonl")
	_ = os.Remove(readyPath)

	certificate, _, err := loadOrCreateFixtureTLS(caPath, caKeyPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	eventFile, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventFile.Chmod(0600); err != nil {
		eventFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eventFile.Close() })
	eventLogger := slog.New(slog.NewJSONHandler(eventFile, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey, "stage", "error_code":
				return attr
			default:
				return slog.Attr{}
			}
		},
	}))
	cfg := Config{
		Listen:  nodeFixtureListen,
		Origin:  nodeFixtureOrigin(t),
		DataDir: stateDir,
	}
	app, err := newServer(cfg, eventLogger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })

	metadata, err := loadOrCreateNodeFixtureMetadata(app, metadataPath, role, caPath, cfg.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Role != role || metadata.HubURL != cfg.Origin || metadata.CAPath != caPath {
		t.Fatal("persistent Node fixture metadata does not match this role or origin")
	}
	if err := writePrivateJSON(metadataPath, metadata); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", nodeFixtureListen)
	if err != nil {
		t.Fatalf("listen %s: %v", nodeFixtureListen, err)
	}
	server := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(tls.NewListener(listener, server.TLSConfig))
	}()
	if err := writeAtomicFile(readyPath, []byte("node-hub-fixture-ready\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Log("Node Hub HTTPS/SQLite fixture ready")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	select {
	case <-signals:
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("fixture HTTPS server stopped: %v", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func prepareFixtureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("Node fixture directory must be a private directory without symlinks")
	}
	return nil
}

// fixtureOriginHost keeps the runner loopback default while letting the
// disposable-VM chain advertise the QEMU slirp route. Only exact known-good
// hosts are accepted: 127.0.0.1 for runner-local review, 10.0.2.2 for the
// guest path that carries Host=10.0.2.2:19443 (server.go rejects any other
// Host with HOST_REJECTED, so anything else would 403 the pairing flow).
func fixtureOriginHost() (string, error) {
	raw := strings.TrimSpace(os.Getenv("MESHMUX_NODE_HUB_FIXTURE_ORIGIN_HOST"))
	if raw == "" {
		return "127.0.0.1", nil
	}
	if raw != "127.0.0.1" && raw != "10.0.2.2" {
		return "", errors.New("fixture Origin host must be 127.0.0.1 or 10.0.2.2")
	}
	return raw, nil
}

func nodeFixtureOrigin(t *testing.T) string {
	t.Helper()
	host, err := fixtureOriginHost()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(nodeFixtureListen)
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + host + ":" + port
}

func loadOrCreateNodeFixtureMetadata(app *Server, path string, role node.Role, caPath string, origin string) (nodeFixtureMetadata, error) {
	var metadata nodeFixtureMetadata
	sshPort, err := fixtureSSHPort()
	if err != nil {
		return metadata, err
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &metadata); err != nil {
			return metadata, errors.New("Node fixture metadata is invalid")
		}
		existing, err := app.store.getNodeAt(metadata.NodeID, app.now())
		if err != nil {
			return metadata, errors.New("persistent Node fixture database has no matching node")
		}
		if existing.Role != string(role) || existing.VlessPort != 8443 || existing.SSHPort != sshPort {
			return metadata, errors.New("persistent Node fixture node does not match its role or ports")
		}
		return metadata, nil
	} else if !os.IsNotExist(err) {
		return metadata, err
	}
	created, code, err := app.store.createNode(string(role), "vm-fixture-"+string(role), 8443, sshPort, app.now())
	if err != nil {
		return metadata, err
	}
	return nodeFixtureMetadata{
		HubURL:      origin,
		NodeID:      created.ID,
		Role:        role,
		VLESSPort:   8443,
		SSHPort:     sshPort,
		PairingCode: code,
		CAPath:      caPath,
	}, nil
}

// fixtureSSHPort keeps the VM guest listener honest: the disposable Debian
// 13 VM only runs sshd on 22, while local review keeps the 2222 default.
// Only exact known-good values are accepted.
func fixtureSSHPort() (int, error) {
	raw := strings.TrimSpace(os.Getenv("MESHMUX_NODE_HUB_FIXTURE_SSH_PORT"))
	if raw == "" {
		return 2222, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 || n == 8443 {
		return 0, errors.New("fixture SSH port must be 1-65535 and differ from the VLESS port")
	}
	return n, nil
}

func loadOrCreateFixtureTLS(caPath, caKeyPath, certPath, keyPath string) (tls.Certificate, *x509.Certificate, error) {
	if fileExists(caPath) && fileExists(caKeyPath) && fileExists(certPath) && fileExists(keyPath) {
		certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, nil, errors.New("fixture TLS keypair is invalid")
		}
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		block, _ := pem.Decode(caPEM)
		if block == nil {
			return tls.Certificate{}, nil, errors.New("fixture CA is invalid")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return tls.Certificate{}, nil, errors.New("fixture CA is invalid")
		}
		return certificate, ca, nil
	}

	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caSerial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "MeshMux disposable Node VM fixture CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafSerial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "MeshMux Node VM fixture"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// 10.0.2.2 is the QEMU slirp route from the guest to the runner
		// loopback where the fixture listens; 127.0.0.1 keeps runner-local
		// review working.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.2")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	for path, data := range map[string][]byte{
		caPath:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		caKeyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}),
		certPath:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPath:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
	} {
		if err := writeAtomicFile(path, data, 0600); err != nil {
			return tls.Certificate{}, nil, err
		}
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return certificate, ca, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func writePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomicFile(path, append(data, '\n'), 0600)
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace fixture file: %w", err)
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
