package jwt

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("suglider")

type jwtData struct {
	Mail string `json:"mail"`
	jwt.RegisteredClaims
}

func GenerateJWT(mail string) (string, int, error) {

	// Declare the expiration time of the token
	expireTime := 20 * time.Minute
	expirationTime := time.Now().Add(expireTime)

	// Create the JWT claims, which includes the username and expiry time
	claims := &jwtData{
		Mail: mail,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", 0, err
	}

	// Convert to Second
	expireTimeSec := int(expireTime.Seconds())

	return tokenString, expireTimeSec, nil
}

func ParseJWT(token string) (*jwtData, int64, error) {

	var errCode int64
	errCode = 0

	claims := &jwtData{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			errorMessage := fmt.Sprintf("JWT signature is invalid: %v", err)
			slog.Error(errorMessage)
			errCode = 1015

			return nil, errCode, err
		}
		errorMessage := fmt.Sprintf("Parse JWT claim data failed: %v", err)
		slog.Error(errorMessage)
		errCode = 1016
		return nil, errCode, err
	}
	if !tkn.Valid {
		errorMessage := fmt.Sprintf("Token is invalid: %v", err)
		slog.Error(errorMessage)
		errCode = 1017

		return nil, errCode, err
	}

	return claims, errCode, nil

}

func RefreshJWT(token string) (string, int, error) {

	claims := &jwtData{}

	jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})

	// Now, create a new token for the current use, with a renewed expiration time
	expireTime := 20 * time.Minute
	expirationTime := time.Now().Add(expireTime)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		return "", 0, err
	}

	// Convert to Second
	expireTimeSec := int(expireTime.Seconds())

	return tokenString, expireTimeSec, nil

}
