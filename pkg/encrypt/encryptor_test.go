package encrypt

import (
	"testing"
	"fmt"
)

func TestEncrypt(t *testing.T) {
	t.Run("Test password hash in Parallel", func(t *testing.T) {
		t.Parallel()
		pwd := RandomString(16, "!@#$%^&*()")
		hashed, err := SaltedPasswordHash(pwd, 12)
		if err != nil {
			t.Errorf("Unit Test (Hash Slated Password) Fail: %v\n", err)
		}
		matched := VerifySaltedPasswordHash(hashed, pwd)
		if ! matched {
			t.Errorf("Result: %v (%s)\n", matched, "The result of salted password verrification is not correct.")
		}
		matched = VerifySaltedPasswordHash(hashed, "tEstP@sS^ord000000000000000")
		if matched {
			t.Errorf("Result: %v (%s)\n", matched, "The result of salted password verrification is not correct.")
		}
	})
	t.Run("Test aes encryption/decryption in Parallel", func(t *testing.T) {
		t.Parallel()
		text := []byte("This is a test for aes encryption/decryption.")
		secret := []byte(RandomString(32, "!@#$%^&*()"))

		encrypted, err := AesEncrypt(secret, text,"CBC")
		if err != nil {
			t.Errorf("Unit Test (AES-CBC encrypt) Fail: %v\n", err)
		}
		decrypted, err := AesDecrypt(secret, encrypted, "CBC")
		if err != nil {
			t.Errorf("Unit Test (AES-CBC decrypt) Fail: %v\n", err)
		}
		if string(text) != string(decrypted) {
			t.Errorf(
				"AES-CBC Test Result:\n    Origin Data: %s\n    Decrypted Data: %s\n    (%s)\n",
				string(text),
				string(decrypted),
				"The decrypted data must be the same as origin data.",
			)
		}

		if encrypted, err = AesEncrypt(secret, text,"ECB"); err != nil {
			t.Errorf("Unit Test (AES-ECB encrypt) Fail: %v\n", err)
		}
		if decrypted, err = AesDecrypt(secret, encrypted, "ECB"); err != nil {
			t.Errorf("Unit Test (AES-ECB decrypt) Fail: %v\n", err)
		}
		if string(text) != string(decrypted) {
			t.Errorf(
				"AES-ECB Test Result:\n    Origin Data: %s\n    Decrypted Data: %s\n    (%s)\n",
				string(text),
				string(decrypted),
				"The decrypted data must be the same as origin data.",
			)
		}

		if encrypted, err = AesEncrypt(secret, text,"CFB"); err != nil {
			t.Errorf("Unit Test (AES-CFB encrypt) Fail: %v\n", err)
		}
		if decrypted, err = AesDecrypt(secret, encrypted, "CFB"); err != nil {
			t.Errorf("Unit Test (AES-CFB decrypt) Fail: %v\n", err)
		}
		if string(text) != string(decrypted) {
			t.Errorf(
				"AES-CFB Test Result:\n    Origin Data: %s\n    Decrypted Data: %s\n    (%s)\n",
				string(text),
				string(decrypted),
				"The decrypted data must be the same as origin data.",
			)
		}
	})
	t.Run("Test rsa encryption/decryption in Parallel", func(t *testing.T) {
		t.Parallel()
		msg := "This is a test for rsa encryption/decryption."
		privkey, pubkey, err := GenerateRSAKeyPair(4096)
		if err != nil {
			t.Errorf("Unit Test (Generate RSA Private/Public Keys) Fail: %v\n", err)
		}
		re := &RsaEncryptor {
			Privkey:       privkey,
			Pubkey:        pubkey,
			HasAlgorithm:  "sha512",
		}

		re.Method = "PKCS1v15"
		encrypted, err := re.RsaEncrypt(msg)
		if err != nil {
			t.Errorf("Unit Test (RSA-PKCS1v15 encrypt) Fail: %v\n", err)
		}
		decrypted, err := re.RsaDecrypt(encrypted)
		if err != nil {
			t.Errorf("Unit Test (RSA-PKCS1v15 decrypt) Fail: %v\n", err)
		}
		if msg != decrypted {
			t.Errorf(
				"RSA (PKCS1v15) Test Result:\n    Origin Data: %s\n    Decrypted Data: %s\n    (%s)\n",
				msg,
				decrypted,
				"The decrypted data must be the same as origin data.",
			)
		}

		signature, err := re.Sign(msg)
		if err != nil {
			t.Errorf("Unit Test (RSA-PKCS1v15 sign) Fail: %v\n", err)
		}
		if err = re.Verify(msg, signature); err != nil {
			t.Errorf("Unit Test (RSA-PKCS1v15 verify) Fail: %v\n", err)
		}
		if err = re.Verify("test_failure", signature); err == nil {
			t.Errorf("Unit Test (RSA-PKCS1v15 negtive-verify) Fail: Must be fail for this test\n")
		}

		re.Method = "OAEP"
		if encrypted, err = re.RsaEncrypt(msg); err != nil {
			t.Errorf("Unit Test (RSA-OAEP encrypt) Fail: %v\n", err)
		}
		if decrypted, err = re.RsaDecrypt(encrypted); err != nil {
			t.Errorf("Unit Test (RSA-OAEP decrypt) Fail: %v\n", err)
		}
		if msg != decrypted {
			t.Errorf(
				"RSA (OAEP) Test Result:\n    Origin Data: %s\n    Decrypted Data: %s\n    (%s)\n",
				msg,
				decrypted,
				"The decrypted data must be the same as origin data.",
			)
		}

		re.SignMethod = "PSS"
		if signature, err = re.Sign(msg); err != nil {
			t.Errorf("Unit Test (RSA-PSS sign) Fail: %v\n", err)
		}
		if err = re.Verify(msg, signature); err != nil {
			t.Errorf("Unit Test (RSA-PSS verify) Fail: %v\n", err)
		}
		if err = re.Verify("test_failure", signature); err == nil {
			t.Errorf("Unit Test (RSA-PSS negtive-verify) Fail: Must be fail for this test\n")
		}
	})
}

func TestKeyPairPem(t *testing.T) {
	privkey, pubkey, err := GenerateRSAKeyPair(4096)
	if err != nil {
		t.Errorf("Unit Test (Generate RSA Private/Public Keys) Fail: %v\n", err)
	}
	privPem, err := RsaPrivateKeyToPem(privkey)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Private Key to PEM) Fail: %v\n", err)
	}
	fmt.Printf("Private Key PEM:\n%s\n", privPem)
	pubPem, err := RsaPublicKeyToPem(pubkey)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Public Key to PEM) Fail: %v\n", err)
	}
	fmt.Printf("Public Key PEM:\n%s\n", pubPem)
	priv, err := RsaPrivateKeyFromPem(privPem)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Private Key from PEM) Fail: %v\n", err)
	}
	pub, err := RsaPublicKeyFromPem(pubPem)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Public Key from PEM) Fail: %v\n", err)
	}

	privPemSec, err := RsaPrivateKeyToPem(priv)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Private Key to PEM) Fail: %v\n", err)
	}
	pubPemSec, err := RsaPublicKeyToPem(pub)
	if err != nil {
		t.Errorf("Unit Test (Convert RSA Public Key to PEM) Fail: %v\n", err)
	}
	if privPem != privPemSec {
		t.Errorf(
			"RSA (RSA Private Key Convert) Test Fail: %s\n",
			"The private key and key from pem must be the same.",
		)
	}
	if pubPem != pubPemSec {
		t.Errorf(
			"RSA (RSA Public Key Convert) Test Fail: %s\n",
			"The public key and key from pem must be the same.",
		)
	}
}
