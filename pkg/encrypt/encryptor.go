package encrypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

func HashWithSHA(data, length string) string {
	var hsh hash.Hash
	switch length {
	case "sha1", "sha128":
		hsh = sha1.New()
	case "sha256":
		hsh = sha256.New()
	default:
		hsh = sha512.New()
	}
	hsh.Write([]byte(data))
	sm := hsh.Sum(nil)
	return fmt.Sprintf("%x",sm)
}

func HashWithMD5(data string) string {
	hsh := md5.New()
	sm := hsh.Sum(nil)
	hsh.Write([]byte(data))
	return fmt.Sprintf("%x",sm)
}

func AesEncrypt(key, data []byte, mode string) ([]byte, error) {
	var result []byte
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := blk.BlockSize()

	switch mode {
	case "ECB", "ecb":
		length := ( len(data) + aes.BlockSize ) / aes.BlockSize
		cont := make([]byte, (length * aes.BlockSize))
		copy(cont, data)
		pad := byte(len(cont) - len(data))
		for n := len(data); n < len(cont); n++ {
			cont[n] = pad
		}
		result = make([]byte, len(cont))
		for start, end := 0, size;
		  start <= len(data) ;
		  start, end = start + size, end + size {
			blk.Encrypt(result[start:end], cont[start:end])
		}

	case "CFB", "cfb":
		result = make([]byte, aes.BlockSize + len(data))
		meta := result[:aes.BlockSize]
		_, err := io.ReadFull(rand.Reader, meta)
		if err != nil {
			return nil, err
		}
		str := cipher.NewCFBEncrypter(blk, meta)
		str.XORKeyStream(result[aes.BlockSize:], data)

	default:
		padding := Pkcs5Pad(data, size)
		result = make([]byte, len(padding))
		encrypter := cipher.NewCBCEncrypter(blk, key[:size])
		encrypter.CryptBlocks(result, padding)
	}

	return result, nil
}

func AesDecrypt(key, data []byte, mode string) ([]byte, error) {
	var result []byte
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := blk.BlockSize()

	switch mode {
	case "ECB", "ecb":
		result = make([]byte, len(data))
		for start, end := 0, size; start < len(data);
		  start, end = start + size, end + size {
			blk.Decrypt(result[start:end], data[start:end])
		}
		byteTrim := 0
		if len(result) > 0 {
			byteTrim = len(result) - int(result[len(result) - 1])
		}
		result = result[:byteTrim]

	case "CFB", "cfb":
		if len(data) < aes.BlockSize {
			return nil, fmt.Errorf("Error: %s\n", "invalid cipher text")
		}
		meta := data[:aes.BlockSize]
		result = data[aes.BlockSize:]
		str := cipher.NewCFBDecrypter(blk, meta)
		str.XORKeyStream(result, result)

	default:
		encrypter := cipher.NewCBCDecrypter(blk, key[:size])
		result = make([]byte, len(data))
		encrypter.CryptBlocks(result, data)
	}

	return result, nil
}

func Pkcs5Pad(data []byte, blkSize int) []byte {
	// eg. []byte{0x0A, 0x0B, 0x0C, 0x0D} to []byte{0x0A, 0x0B, 0x0C, 0x0D, 0x04, 0x04, 0x04, 0x04}
	length := blkSize - (len(data) % blkSize)
	newKey := bytes.Repeat([]byte{byte(length)}, length)
	return newKey
}

func Pkcs5Unpad(data []byte, blkSize int) ([]byte, error) {
	length    := len(data)
	padLength := int(data[length-1])
	if length == 0 || padLength > blkSize || padLength > length {
		return nil, fmt.Errorf("Unpad Error: %s\n", "invalid padding size")
	}
	if padLength == 0 {
		return nil, fmt.Errorf("Unpad Error: %s\n", "invalid last byte")
	}
	origin := data[:(length - padLength)]
	return origin, nil
}

type RsaEncryptor struct {
	Privkey       *rsa.PrivateKey
	Pubkey        *rsa.PublicKey
	Method        string             // "OAEP" or "PKCS1v15"
	SignMethod    string             // "PSS" or "PKCS1v15"
	HasAlgorithm  string             // "sha1", "sha512" or "sha256"
}

func (re *RsaEncryptor) RsaEncrypt(data string) (string, error) {
	var (
		encrypted []byte
		err       error
		hsh       hash.Hash
	)
	switch re.HasAlgorithm {
	case "sha1", "sha128":
		hsh = sha1.New()
	case "sha512":
		hsh = sha512.New()
	default:
		hsh = sha256.New()
	}
	switch re.Method {
	case "pkcs1", "pkcs1v15", "PKCS1v15", "PKCS1":
		if encrypted ,err = rsa.EncryptPKCS1v15(
			rand.Reader,
			re.Pubkey,
			[]byte(data),
		); err != nil {
			return "", err
		}
	default:
		if encrypted, err = rsa.EncryptOAEP(
			hsh,
			rand.Reader,
			re.Pubkey,
			[]byte(data),
			nil,
		); err != nil {
			return "", err
		}
	}
	return string(encrypted), nil
}

func (re *RsaEncryptor) RsaDecrypt(data string) (string, error) {
	var (
		decrypted []byte
		err       error
		hsh       crypto.Hash
	)
	switch re.HasAlgorithm {
	case "sha1", "sha128":
		hsh = crypto.SHA1
	case "sha512":
		hsh = crypto.SHA512
	default:
		hsh = crypto.SHA256
	}
	switch re.Method {
	case "pkcs1", "pkcs1v15", "PKCS1v15", "PKCS1":
		if decrypted, err = rsa.DecryptPKCS1v15(
			rand.Reader,
			re.Privkey,
			[]byte(data),
		); err != nil {
			return "", err
		}
	default:
		if decrypted, err = re.Privkey.Decrypt(
			nil,
			decrypted,
			&rsa.OAEPOptions {
				Hash: hsh,
			},
		); err != nil {
			return "", err
		}
	}
	return string(decrypted), nil
}

func (re *RsaEncryptor) Sign(data string) (string, error) {
	var (
		signature  []byte
		err        error
		hsh        hash.Hash
		crpthash   crypto.Hash
	)
	switch re.HasAlgorithm {
	case "sha1", "sha128":
		hsh = sha1.New()
		crpthash = crypto.SHA1
	case "sha512":
		hsh = sha512.New()
		crpthash = crypto.SHA512
	default:
		hsh = sha256.New()
		crpthash = crypto.SHA256
	}
	if _, err = hsh.Write([]byte(data)); err != nil {
		return "", err
	}
	hashed := hsh.Sum(nil)
	switch re.SignMethod {
	case "pkcs1", "pkcs1v15", "PKCS1v15", "PKCS1":
		if signature, err = rsa.SignPKCS1v15(
			rand.Reader,
			re.Privkey,
			crpthash,
			hashed,
		); err != nil {
			return "", err
		}
	default:
		if signature, err = rsa.SignPSS(
			rand.Reader,
			re.Privkey,
			crpthash,
			hashed,
			nil,
		); err != nil {
			return "", err
		}
	}
	return string(signature), nil
}

func (re *RsaEncryptor) Verify(data, signature string) error {
	var (
		err        error
		hsh        hash.Hash
		crpthash   crypto.Hash
	)
	switch re.HasAlgorithm {
	case "sha1", "sha128":
		hsh = sha1.New()
		crpthash = crypto.SHA1
	case "sha512":
		hsh = sha512.New()
		crpthash = crypto.SHA512
	default:
		hsh = sha256.New()
		crpthash = crypto.SHA256
	}
	if _, err = hsh.Write([]byte(data)); err != nil {
		return err
	}
	hashed := hsh.Sum(nil)
	switch re.SignMethod {
	case "pkcs1", "pkcs1v15", "PKCS1v15", "PKCS1":
		err = rsa.VerifyPKCS1v15(re.Pubkey, crpthash, hashed, []byte(signature))
	default:
		err = rsa.VerifyPSS(re.Pubkey, crpthash, hashed, []byte(signature), nil)
	}
	return err
}
