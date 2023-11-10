package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"fmt"
)

var jwtKey = []byte("suglider")

type jwtData struct {
	Username	string	`json:"username"`
	jwt.RegisteredClaims
}

func GenerateJWT(username string) (string, int, error) {

	// Declare the expiration time of the token
	expirationTime := 3000

	// Create the JWT claims, which includes the username and expiry time
	claims := &jwtData{
		Username: username,
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// TODO
		return "", 0, err
	}

	return tokenString, expirationTime, nil
}

func ParseJWT(token string) (string, error) {

	claims := &jwtData{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			// TODO
			fmt.Println("StatusUnauthorized")
			return "", err
		}
		// TODO
		fmt.Println("StatusBadRequest")
		return "", err
	}
	if !tkn.Valid {
		// TODO
		fmt.Println("StatusUnauthorized")
		return "", err
	}

	fmt.Println(tkn)
	fmt.Println(claims.Username)

	return claims.Username, nil

}

func RefreshJWT(token string) (string, int, error) {

	claims := &jwtData{}

	jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})

	// if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
	// 	// TODO
	// 	fmt.Println("StatusBadRequest")
	// 	return "", 0, err
	// }

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := 3000
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		// TODO
		fmt.Println("StatusInternalServerError")
		return "", 0, err
	}

	return tokenString, expirationTime, nil
	
}