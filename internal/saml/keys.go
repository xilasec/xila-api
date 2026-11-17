package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/secretbox"
)

// KeyPair is the SP's signing/decryption key and its certificate (what the IdP
// is given in our metadata).
type KeyPair struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

// ParseKeyPair reads a PEM certificate + private key (SAML_SP_CERT/SAML_SP_KEY).
func ParseKeyPair(certPEM, keyPEM string) (KeyPair, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return KeyPair{}, fmt.Errorf("SAML_SP_CERT/SAML_SP_KEY: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return KeyPair{}, errors.New("SAML_SP_KEY: unsupported key type")
	}
	if _, isRSA := signer.(*rsa.PrivateKey); !isRSA {
		// Encrypted assertions are key-transported with RSA-OAEP.
		return KeyPair{}, errors.New("SAML_SP_KEY must be an RSA key")
	}
	return KeyPair{Key: signer, Cert: pair.Leaf}, nil
}

// KeyStore persists the generated SP key pair, so every replica (and every
// restart) presents the same certificate to the IdP. The private key is sealed
// with INTEGRATION_SECRET_KEY.
type KeyStore struct {
	db     *pgxpool.Pool
	cipher *secretbox.Keyring
}

// NewKeyStore constructs a KeyStore. An unconfigured cipher (no
// INTEGRATION_SECRET_KEY) makes LoadOrCreate fail with secretbox.ErrNoKey.
func NewKeyStore(db *pgxpool.Pool, cipher *secretbox.Keyring) *KeyStore {
	return &KeyStore{db: db, cipher: cipher}
}

const keyAAD = "saml-sp-key"

// LoadOrCreate returns the stored key pair, generating and storing one first if
// there is none. Replicas booting together race on the single-row insert; the
// losers discard their key and load the winner's.
func (s *KeyStore) LoadOrCreate(ctx context.Context, commonName string) (KeyPair, error) {
	if !s.cipher.Configured() {
		return KeyPair{}, secretbox.ErrNoKey
	}
	if kp, err := s.load(ctx); err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return kp, err
	}
	certPEM, keyPEM, err := generate(commonName)
	if err != nil {
		return KeyPair{}, err
	}
	sealed, err := s.cipher.Seal(keyPEM, keyAAD)
	if err != nil {
		return KeyPair{}, err
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO saml_sp_keys (id, cert_pem, key_enc) VALUES (1, $1, $2)
		ON CONFLICT (id) DO NOTHING`, certPEM, sealed); err != nil {
		return KeyPair{}, fmt.Errorf("store saml sp key: %w", err)
	}
	return s.load(ctx)
}

func (s *KeyStore) load(ctx context.Context) (KeyPair, error) {
	var certPEM string
	var sealed []byte
	if err := s.db.QueryRow(ctx, `SELECT cert_pem, key_enc FROM saml_sp_keys WHERE id = 1`).Scan(&certPEM, &sealed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return KeyPair{}, err
		}
		return KeyPair{}, fmt.Errorf("load saml sp key: %w", err)
	}
	keyPEM, err := s.cipher.Open(sealed, keyAAD)
	if err != nil {
		return KeyPair{}, fmt.Errorf("unseal saml sp key: %w", err)
	}
	return ParseKeyPair(certPEM, keyPEM)
}

// generate makes a self-signed RSA-2048 certificate valid for ten years. IdPs
// use SP certificates as raw keys (no chain validation), so self-signed is the
// norm.
func generate(commonName string) (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate saml sp key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Xila"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("self-sign saml sp cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, nil
}
