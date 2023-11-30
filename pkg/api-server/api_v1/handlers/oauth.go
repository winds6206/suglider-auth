package handlers

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"suglider-auth/configs"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = "randomstate"
)

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

	// Log or print the response body content
	fmt.Println("Response body:", string(body))

	c.JSON(http.StatusOK, gin.H{"message": "Google login successful!"})
}
