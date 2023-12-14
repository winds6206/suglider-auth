package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"net/http"
	"suglider-auth/configs"

	mariadb "suglider-auth/internal/database"
	"suglider-auth/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = "randomstate"
)

// @Summary Google OAuth2 Sign Up
// @Description Registry new user through Google OAuth2.
// @Tags oauth2
// @Accept multipart/form-data
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/oauth/google/sign-up [get]
func OAuthGoogleSignUp(c *gin.Context) {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:9527/api/v1/oauth/google/callback",
		ClientID:     configs.ApplicationConfig.Oauth.Google.ClientID,
		ClientSecret: configs.ApplicationConfig.Oauth.Google.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// @Summary Google OAuth2 Login
// @Description Login through Google OAuth2.
// @Tags oauth2
// @Accept multipart/form-data
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/oauth/google/login [get]
func OAuthGoogleLogin(c *gin.Context) {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:9527/api/v1/oauth/google/callback",
		ClientID:     configs.ApplicationConfig.Oauth.Google.ClientID,
		ClientSecret: configs.ApplicationConfig.Oauth.Google.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func OAuthGoogleCallback(c *gin.Context) {

	var oAuthResponse oAuthResponse

	code := c.Query("code")
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Println("Code exchange failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code"})
		return
	}

	client := googleOauthConfig.Client(oauth2.NoContext, token)
	response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Println("Failed to get user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	defer response.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("Failed to read response body:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response body"})
		return
	}

	if err := json.Unmarshal(body, &oAuthResponse); err != nil {
		log.Println("Failed to parse user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user info"})
		return
	}

	// Check whether the mail exists or not
	count, err := mariadb.CheckMailExists(oAuthResponse.Email)
	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the mail exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1046, err))
	}

	if count == 1 {

		// Check whether user enable 2FA or not.
		userTwoFactorAuthData, err := mariadb.GetTwoFactorAuthByMail(oAuthResponse.Email)

		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// These conditions indicate that user have enabled the 2FA feature.
		if userTwoFactorAuthData.TotpEnabled.Bool ||
			userTwoFactorAuthData.SmsOTPEnabled ||
			userTwoFactorAuthData.MailOTPEnabled {

			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail":             oAuthResponse.Email,
				"username":         userTwoFactorAuthData.UserName,
				"totp_enabled":     userTwoFactorAuthData.TotpEnabled.Bool,
				"mail_otp_enabled": userTwoFactorAuthData.MailOTPEnabled,
				"sms_otp_enabled":  userTwoFactorAuthData.SmsOTPEnabled,
			}))

		} else {
			okSetSession := setSession(c, oAuthResponse.Email)
			okSetJWT := setJWT(c, oAuthResponse.Email)

			if okSetSession && okSetJWT {
				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"mail":    oAuthResponse.Email,
					"message": "Google login successful!",
				}))
			} else {
				return
				// c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, map[string]interface{}{
				// 	"mail":        oAuthResponse.Email,
				// 	"set_session": okSetSession,
				// 	"set_jwt":     okSetJWT,
				// }))
			}
		}
		// if mail is not exist, program will automatic to create
	} else {

		err := mariadb.OAuthSignUp(oAuthResponse.Email, oAuthResponse.GivenName, oAuthResponse.FamilyName)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert user_info table failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// Look up user ID
		userInfo, err := mariadb.LookupUserID(oAuthResponse.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// Insert personal_info table by user_id
		err = mariadb.InsertPersonalInfo(userInfo.UserID)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert personal_info table failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		okSetSession := setSession(c, oAuthResponse.Email)
		okSetJWT := setJWT(c, oAuthResponse.Email)

		if okSetSession && okSetJWT {
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail":    oAuthResponse.Email,
				"message": "Google login successful!",
			}))
		} else {
			return
			// c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, map[string]interface{}{
			// 	"mail":        oAuthResponse.Email,
			// 	"set_session": okSetSession,
			// 	"set_jwt":     okSetJWT,
			// }))
		}
	}

}
