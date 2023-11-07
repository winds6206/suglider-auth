package totp

import (
	"log/slog"
	"fmt"
	"image/png"
	"bytes"
	mariadb "suglider-auth/internal/database"
	"github.com/pquerna/otp/totp"

)

type totpInfo struct {
	Base32  string `json:"base32"`
	AuthURL string `json:"auth_url"`
}

func TotpGernate(username, user_id string) (*totpInfo, []byte) {

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Suglider",
		AccountName: username + "@example.com",
	})
	if err != nil {
		errorMessage := fmt.Sprintf("Generate TOTP key have something problem: %v", err)
		slog.Error(errorMessage)
		return nil, nil
	}

	totpData := &totpInfo {
		Base32:  key.Secret(), 
		AuthURL: key.URL(),
	}

    // Convert TOTP key into a QR code encoded as a PNG image.
    var buf bytes.Buffer
    img, err := key.Image(200, 200)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save QR code: %v", err)
		slog.Error(errorMessage)
		return nil, nil
	}

    errEncode := png.Encode(&buf, img)
	if errEncode != nil {
		errorMessage := fmt.Sprintf("Encode PNG failed: %v", err)
		slog.Error(errorMessage)
		return nil, nil
	}

	count, _ := mariadb.TotpUserCheck(user_id, username)

	if count == 1 {
		errTotpUpdateSecret := mariadb.TotpUpdateSecret(user_id, username, key.Secret(), key.URL())
		if errTotpUpdateSecret != nil {
			errorMessage := fmt.Sprintf("Update totp table failed: %v", err)
			slog.Error(errorMessage)
			return nil, nil
		}
	} else if count == 0 {
		errTotpStoreSecret := mariadb.TotpStoreSecret(user_id, username, key.Secret(), key.URL())
		if errTotpStoreSecret != nil {
			errorMessage := fmt.Sprintf("Insert totp table failed: %v", err)
			slog.Error(errorMessage)
			return nil, nil
		}
	} else {
		errorMessage := fmt.Sprintf("TotpUserCheck() count problem, count=%d",count)
		slog.Error(errorMessage)
		return nil, nil
	}

	return totpData, buf.Bytes()
}

func TotpValidate(totpCode, totpKey string) bool {

	valid := totp.Validate(totpCode, totpKey)

	if valid {
		return true
	} else {
		return false
	}
}

