package api_server

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

// @Summary Show Information (Simple Health Check)
// @Description show the fundamental informations of this server
// @Tags general
// @Accept application/json
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /info [get]
func (aa *AuthApiSettings) healthzHandler(c *gin.Context) {
    c.IndentedJSON(http.StatusOK, gin.H {
        "Name":            aa.Name,
        "Version":         aa.Version,
        "X-FORWARDED-FOR": c.Request.Header.Get("X-Forwarded-For"),
    })
}
