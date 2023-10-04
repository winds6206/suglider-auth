package encrypt

import (
	"os"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
)

func RandomString(length int, specials string) string {
	characters := fmt.Sprintf("0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz%s", specials)
	rand.Seed(time.Now().UnixNano())
	randString := make([]byte, length)
	for n := 0; n < length; n++ {
		randString[n] = characters[rand.Intn(len(characters))]
	}
	return string(randString)
}

func GenertateUUID(noDash bool) string {
	id := uuid.New()
	return id.String()
}

func GenerateRSAKeyPair(length int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if length < 2048 { length = 2048 }
	if (length % 1024) != 0 {
		return nil, nil, fmt.Errorf("Error: %s\n", "length must be multiple of 1024")
	}
	privKey, err := rsa.GenerateKey(crand.Reader, length)
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey
	return privKey, &pubKey, nil
}

func RsaPrivateKeyToPem(key *rsa.PrivateKey) (string, error) {
	privkey := x509.MarshalPKCS1PrivateKey(key)
	keyPem := pem.EncodeToMemory(
		&pem.Block {
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey,
		},
	)
	return string(keyPem), nil
}

func RsaPrivateKeyToPemFile(key *rsa.PrivateKey, file string) error {
	privkey := x509.MarshalPKCS1PrivateKey(key)
	keyPem := pem.EncodeToMemory(
		&pem.Block {
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey,
		},
	)
	if err := os.WriteFile(file, keyPem, 0600); err != nil {
		return err
	}
	return nil
}

func RsaPrivateKeyFromPem(key string) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(key))
	if blk == nil {
		return nil, fmt.Errorf("Error: %s\n", "fail to parse pem")
	}
	privkey, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

func RsaPrivateKeyFromPemFile(file string) (*rsa.PrivateKey, error) {
	key, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	privkey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

func RsaPublicKeyToPem(key *rsa.PublicKey) (string, error) {
	pubkey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	keyPem := pem.EncodeToMemory(
		&pem.Block {
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey,
		},
	)
	return string(keyPem), nil
}

func RsaPublicKeyToPemFile(key *rsa.PublicKey, file string) error {
	pubkey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	keyPem := pem.EncodeToMemory(
		&pem.Block {
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey,
		},
	)
	if err := os.WriteFile(file, keyPem, 0644); err != nil {
		return err
	}
	return nil
}

func RsaPublicKeyFromPem(key string) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode([]byte(key))
	if blk == nil {
		return nil, fmt.Errorf("Error: %s\n", "fail to parse pem")
	}
	pubkey, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	switch pubkey := pubkey.(type) {
	case *rsa.PublicKey:
		return pubkey, nil
	default:
	}
	return nil, fmt.Errorf("Error: %s\n", "")
}

func RsaPublicKeyFromPemFile(file string) (*rsa.PublicKey, error) {
	key, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pubkey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	switch pubkey := pubkey.(type) {
	case *rsa.PublicKey:
		return pubkey, nil
	default:
	}
	return nil, fmt.Errorf("Error: %s\n", "")
}

