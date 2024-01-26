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
	"suglider-auth/internal/redis"
	"suglider-auth/pkg/time_convert"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = "randomstate"
)

// @Summary Google OAuth2 Verification
// @Description Verify Google OAuth2 authentication from frontend
// @Tags oauth2
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param token formData string false "Token"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/oauth/google/verify [post]
func OAuthGoogleVerification(c *gin.Context) {
	var (
		oAuthResponse oAuthResponse
		username      string
		err           error
	)

	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
		return
	}

	postData := &googleOauth2Verification{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
		return
	}

	if postData.Mail == "" || postData.AccessToken == "" {
		slog.Error("It's either that the mail doesn't exist or token.")
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1072, nil))
		return
	}

	client := googleOauthConfig.Client(
		oauth2.NoContext,
		&oauth2.Token {
			AccessToken: postData.AccessToken,
			TokenType:   "Bearer",
		 },
	)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Println("Failed to get user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H { "error": "Failed to get user info" })
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response body:", err)
		c.JSON(http.StatusInternalServerError, gin.H { "error": "Failed to read response body" })
		return
	}

	if err = json.Unmarshal(body, &oAuthResponse); err != nil {
		log.Println("Failed to parse user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H { "error": "Failed to parse user info" })
		return
	}

	if postData.Mail != oAuthResponse.Email {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1073, err))
		return
	}

	exist, err := mariadb.CheckMailExists(oAuthResponse.Email)
	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the mail exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1046, err))
	}

	if exist == 1 {
		userTwoFactorAuthData, err := mariadb.GetTwoFactorAuthByMail(oAuthResponse.Email)
		if userTwoFactorAuthData.UserName.Valid {
			// Valid is true if String is not NULL
			username = userTwoFactorAuthData.UserName.String
		} else {
			username = ""
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		if userTwoFactorAuthData.TotpEnabled.Bool ||
			userTwoFactorAuthData.SmsOTPEnabled ||
			userTwoFactorAuthData.MailOTPEnabled {

			userNameData := &UserName {
				String: username,
				Valid:  true,
			}

			rdsValue := &rdsValeData {
				Mail:           oAuthResponse.Email,
				UserName:       *userNameData,
				AccountPassed:  true,
				MailOTPPassed:  false,
				SmsOTPPassed:   false,
				TotpPassed:     false,
				TotpEnabled:    userTwoFactorAuthData.TotpEnabled.Bool,
				MailOTPEnabled: userTwoFactorAuthData.MailOTPEnabled,
				SmsOTPEnabled:  userTwoFactorAuthData.SmsOTPEnabled,
			}

			jsonData, err := json.Marshal(rdsValue)
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
				return
			}

			redisTTL, _, err := time_convert.ConvertTimeFormat("15m")
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1069, err))
				return
			}

			err = redis.Set("login_status:" + oAuthResponse.Email, string(jsonData), redisTTL)

			if err != nil {
				errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
				slog.Error(errorMessage)
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
				return
			}

			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail":             oAuthResponse.Email,
				"username":         *userNameData,
				"totp_enabled":     userTwoFactorAuthData.TotpEnabled.Bool,
				"totp_passed":      false,
				"mail_otp_enabled": userTwoFactorAuthData.MailOTPEnabled,
				"mail_otp__passed": false,
				"sms_otp_enabled":  userTwoFactorAuthData.SmsOTPEnabled,
				"sms_otp_passed":   false,
			}))

		} else {
			okSetSession := setSession(c, oAuthResponse.Email)
			okSetJWT := setJWT(c, oAuthResponse.Email)

			userNameData := &UserName {
				String: username,
				Valid:  true,
			}

			rdsValue := &rdsValeData {
				Mail:           oAuthResponse.Email,
				UserName:       *userNameData,
				AccountPassed:  true,
				MailOTPPassed:  false,
				SmsOTPPassed:   false,
				TotpPassed:     false,
				TotpEnabled:    userTwoFactorAuthData.TotpEnabled.Bool,
				MailOTPEnabled: userTwoFactorAuthData.MailOTPEnabled,
				SmsOTPEnabled:  userTwoFactorAuthData.SmsOTPEnabled,
			}

			jsonData, err := json.Marshal(rdsValue)
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
				return
			}

			redisTTL, _, err := time_convert.ConvertTimeFormat("15m")
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1069, err))
				return
			}

			err = redis.Set("login_status:" + oAuthResponse.Email, string(jsonData), redisTTL)

			if err != nil {
				errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
				slog.Error(errorMessage)
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
				return
			}

			if okSetSession && okSetJWT {
				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"mail":             oAuthResponse.Email,
					"username":         *userNameData,
					"totp_enabled":     userTwoFactorAuthData.TotpEnabled.Bool,
					"totp_passed":      false,
					"mail_otp_enabled": userTwoFactorAuthData.MailOTPEnabled,
					"mail_otp__passed": false,
					"sms_otp_enabled":  userTwoFactorAuthData.SmsOTPEnabled,
					"sms_otp_passed":   false,
				}))
			} else {
				return
			}
		}
	} else {
		err = mariadb.OAuthSignUp(oAuthResponse.Email, oAuthResponse.GivenName, oAuthResponse.FamilyName)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert user_info table failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		if err = mariadb.UserSetMailVerified(c, oAuthResponse.Email); err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1023, err))
			return
		}

		userInfo, err := mariadb.LookupUserID(oAuthResponse.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		err = mariadb.InsertPersonalInfo(userInfo.UserID)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert personal_info table failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		okSetSession := setSession(c, oAuthResponse.Email)
		okSetJWT := setJWT(c, oAuthResponse.Email)

		userNameData := &UserName{
			String: "",
			Valid:  true,
		}

		rdsValue := &rdsValeData{
			Mail:           oAuthResponse.Email,
			UserName:       *userNameData,
			AccountPassed:  true,
			MailOTPPassed:  false,
			SmsOTPPassed:   false,
			TotpPassed:     false,
			TotpEnabled:    false,
			MailOTPEnabled: false,
			SmsOTPEnabled:  false,
		}

		jsonData, err := json.Marshal(rdsValue)
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
			return
		}

		redisTTL, _, err := time_convert.ConvertTimeFormat("15m")
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1069, err))
			return
		}

		err = redis.Set("login_status:" + oAuthResponse.Email, string(jsonData), redisTTL)

		if err != nil {
			errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
			return
		}

		if okSetSession && okSetJWT {
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail":             oAuthResponse.Email,
				"username":         *userNameData,
				"totp_enabled":     false,
				"totp_passed":      false,
				"mail_otp_enabled": false,
				"mail_otp__passed": false,
				"sms_otp_enabled":  false,
				"sms_otp_passed":   false,
			}))
		} else {
			return
		}
	}
}

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
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Println("Failed to get user info:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
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
