package totp

import (
	"bytes"
	"fmt"
	"image/png"
	"log/slog"
	mariadb "suglider-auth/internal/database"

	"github.com/pquerna/otp/totp"
)

type totpInfo struct {
	Base32  string `json:"base32"`
	AuthURL string `json:"auth_url"`
}

func TotpGernate(username, userID string) (*totpInfo, []byte, int64, error) {

	var errCode int64
	errCode = 0

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Suglider",
		AccountName: username + "@example.com",
	})
	if err != nil {
		errorMessage := fmt.Sprintf("Generate TOTP key have something problem: %v", err)
		slog.Error(errorMessage)
		errCode = 1008
		return nil, nil, errCode, err
	}

	totpData := &totpInfo{
		Base32:  key.Secret(),
		AuthURL: key.URL(),
	}

	// Convert TOTP key into a QR code encoded as a PNG image.
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		errorMessage := fmt.Sprintf("Failed to save QR code: %v", err)
		slog.Error(errorMessage)
		errCode = 1009
		return nil, nil, errCode, err
	}

	errEncode := png.Encode(&buf, img)
	if errEncode != nil {
		errorMessage := fmt.Sprintf("Encode PNG failed: %v", err)
		slog.Error(errorMessage)
		errCode = 1010
		return nil, nil, errCode, errEncode
	}

	// Check whether the user_id exists in the totp table or not.
	count, err := mariadb.TotpUserCheck(userID)

	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the user_id exists or not failed: %v", err)
		slog.Error(errorMessage)
		errCode = 1011
		return nil, nil, errCode, err
	}

	if count == 1 {
		err := mariadb.TotpUpdateSecret(username, key.Secret(), key.URL())
		if err != nil {
			errorMessage := fmt.Sprintf("Update totp table failed: %v", err)
			slog.Error(errorMessage)
			errCode = 1012
			return nil, nil, errCode, err
		}
	} else {
		err := mariadb.TotpStoreSecret(userID, key.Secret(), key.URL())
		if err != nil {
			errorMessage := fmt.Sprintf("Insert totp table failed: %v", err)
			slog.Error(errorMessage)
			errCode = 1013
			return nil, nil, errCode, err
		}
	}

	return totpData, buf.Bytes(), errCode, nil
}

func TotpValidate(totpCode, totpKey string) bool {

	valid := totp.Validate(totpCode, totpKey)

	if valid {
		return true
	} else {
		return false
	}
}
