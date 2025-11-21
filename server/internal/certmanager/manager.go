package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

const (
	caCertFile     = "ca.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server.pem"
	serverKeyFile  = "server-key.pem"
)

// Manager handles CA/server certificate lifecycle and issuance.
type Manager struct {
	cfg    config.PKIConfig
	logger *slog.Logger

	mu         sync.RWMutex
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      []byte
	serverCert tls.Certificate
	serverPEM  []byte
	caPool     *x509.CertPool
}

// RotationResult describes a rotate operation outcome.
type RotationResult struct {
	CAPEM        []byte
	ServerPEM    []byte
	CANotAfter   time.Time
	ServerExpiry time.Time
}

// AgentBundle contains issued client certificate/key pair.
type AgentBundle struct {
	CertPEM   []byte
	KeyPEM    []byte
	CAPEM     []byte
	ExpiresAt time.Time
}

// New creates a new cert manager based on configuration.
func New(cfg config.PKIConfig, logger *slog.Logger) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cert storage: %w", err)
	}
	mgr := &Manager{cfg: cfg, logger: logger}
	if err := mgr.loadOrInit(); err != nil {
		return nil, err
	}
	return mgr, nil
}

// TLSConfig returns a tls.Config using the managed certificates.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: m.clientAuthMode(),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			return &m.serverCert, nil
		},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				ClientAuth: m.clientAuthMode(),
				ClientCAs:  m.caPool,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &m.serverCert, nil
				},
			}, nil
		},
	}
}

// Rotate rotates CA and server certificates atomically.
func (m *Manager) Rotate() (RotationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.logger != nil {
		m.logger.Info("certmanager: rotating certificates")
	}

	newCA, newCAKey, newCAPEM, err := m.generateCA()
	if err != nil {
		return RotationResult{}, err
	}
	newServerCert, newServerPEM, newServerKeyPEM, err := m.generateServerCert(newCA, newCAKey)
	if err != nil {
		return RotationResult{}, err
	}

	if err := m.persist(caCertFile, newCAPEM); err != nil {
		return RotationResult{}, err
	}
	if err := m.persist(caKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(newCAKey)})); err != nil {
		return RotationResult{}, err
	}
	if err := m.persist(serverCertFile, newServerPEM); err != nil {
		return RotationResult{}, err
	}
	if err := m.persist(serverKeyFile, newServerKeyPEM); err != nil {
		return RotationResult{}, err
	}

	m.applySnapshots(newCA, newCAKey, newCAPEM, newServerCert, newServerPEM)

	return RotationResult{
		CAPEM:        newCAPEM,
		ServerPEM:    newServerPEM,
		CANotAfter:   newCA.NotAfter,
		ServerExpiry: newServerCert.Leaf.NotAfter,
	}, nil
}

// CACertificate returns PEM bytes and expiry for CA bundle.
func (m *Manager) CACertificate() ([]byte, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.caPEM...), m.caCert.NotAfter
}

// ServerCertificate returns PEM bytes and expiry for current server cert.
func (m *Manager) ServerCertificate() ([]byte, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.serverPEM...), m.serverCert.Leaf.NotAfter
}

// IssueAgentCertificate mints a client certificate for the given subject.
func (m *Manager) IssueAgentCertificate(commonName string, ttlOverride time.Duration) (AgentBundle, error) {
	if strings.TrimSpace(commonName) == "" {
		return AgentBundle{}, errors.New("common_name is required")
	}
	ttl := m.cfg.AgentCertTTL
	if ttlOverride > 0 {
		ttl = ttlOverride
	}
	if ttl <= 0 {
		return AgentBundle{}, errors.New("agent cert ttl must be positive")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return AgentBundle{}, fmt.Errorf("generate agent key: %w", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: bigSerial(),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{m.cfg.Organization},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(ttl),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return AgentBundle{}, fmt.Errorf("sign agent cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return AgentBundle{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CAPEM:     append([]byte(nil), m.caPEM...),
		ExpiresAt: tpl.NotAfter,
	}, nil
}

func (m *Manager) loadOrInit() error {
	caCertPath := filepath.Join(m.cfg.StorageDir, caCertFile)
	caKeyPath := filepath.Join(m.cfg.StorageDir, caKeyFile)
	serverCertPath := filepath.Join(m.cfg.StorageDir, serverCertFile)
	serverKeyPath := filepath.Join(m.cfg.StorageDir, serverKeyFile)

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read ca cert: %w", err)
		}
		if err := m.initCA(); err != nil {
			return err
		}
		caCertPEM, err = os.ReadFile(caCertPath)
		if err != nil {
			return fmt.Errorf("read ca cert: %w", err)
		}
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("read ca key: %w", err)
	}
	serverCertPEM, err := os.ReadFile(serverCertPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read server cert: %w", err)
		}
		if err := m.initServerCert(); err != nil {
			return err
		}
		serverCertPEM, err = os.ReadFile(serverCertPath)
		if err != nil {
			return fmt.Errorf("read server cert: %w", err)
		}
	}
	serverKeyPEM, err := os.ReadFile(serverKeyPath)
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}

	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	serverCert, err := loadServerCertificate(serverCertPEM, serverKeyPEM)
	if err != nil {
		return err
	}
	m.applySnapshots(caCert, caKey, caCertPEM, serverCert, serverCertPEM)
	return nil
}

func (m *Manager) initCA() error {
	cert, key, pemBytes, err := m.generateCA()
	if err != nil {
		return err
	}
	if err := m.persist(caCertFile, pemBytes); err != nil {
		return err
	}
	if err := m.persist(caKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})); err != nil {
		return err
	}
	m.caCert = cert
	m.caKey = key
	m.caPEM = pemBytes
	m.caPool = x509.NewCertPool()
	m.caPool.AddCert(cert)
	return nil
}

func (m *Manager) initServerCert() error {
	if m.caCert == nil || m.caKey == nil {
		return errors.New("CA must be initialized before server cert")
	}
	serverCert, serverPEM, serverKeyPEM, err := m.generateServerCert(m.caCert, m.caKey)
	if err != nil {
		return err
	}
	if err := m.persist(serverCertFile, serverPEM); err != nil {
		return err
	}
	if err := m.persist(serverKeyFile, serverKeyPEM); err != nil {
		return err
	}
	m.serverCert = serverCert
	m.serverPEM = serverPEM
	return nil
}

func (m *Manager) generateCA() (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate ca key: %w", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: bigSerial(),
		Subject: pkix.Name{
			CommonName:   m.cfg.CommonName,
			Organization: []string{m.cfg.Organization},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(m.cfg.ServerCertTTL * 2),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create ca cert: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	return cert, key, pemBytes, nil
}

func (m *Manager) generateServerCert(ca *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate server key: %w", err)
	}
	now := time.Now().UTC()
	tpl := &x509.Certificate{
		SerialNumber: bigSerial(),
		Subject: pkix.Name{
			CommonName:   m.cfg.CommonName,
			Organization: []string{m.cfg.Organization},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(m.cfg.ServerCertTTL),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), m.cfg.ServerDNSNames...),
	}
	for _, ipStr := range m.cfg.ServerIPs {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create server cert: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("load server keypair: %w", err)
	}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return pair, certPEM, keyPEM, nil
}

func (m *Manager) applySnapshots(caCert *x509.Certificate, caKey *rsa.PrivateKey, caPEM []byte, serverCert tls.Certificate, serverPEM []byte) {
	m.caCert = caCert
	m.caKey = caKey
	m.caPEM = append([]byte(nil), caPEM...)
	m.serverCert = serverCert
	m.serverPEM = append([]byte(nil), serverPEM...)
	m.caPool = x509.NewCertPool()
	m.caPool.AddCert(caCert)
}

func (m *Manager) persist(name string, data []byte) error {
	if data == nil {
		return nil
	}
	path := filepath.Join(m.cfg.StorageDir, name)
	return os.WriteFile(path, data, 0o600)
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid ca key pem")
	}
	var key *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var any interface{}
		any, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			key, ok = any.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("pkcs8 key is not rsa")
			}
		}
	default:
		err = fmt.Errorf("unsupported key type %s", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	return cert, key, nil
}

func loadServerCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load server tls keypair: %w", err)
	}
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				cert.Leaf = leaf
			}
		}
	}
	return cert, nil
}

func bigSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

func (m *Manager) clientAuthMode() tls.ClientAuthType {
	if m.cfg.RequireClientCert {
		return tls.RequireAndVerifyClientCert
	}
	return tls.NoClientCert
}
