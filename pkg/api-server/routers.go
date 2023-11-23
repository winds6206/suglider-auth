package api_server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"suglider-auth/configs"
	docs "suglider-auth/docs"
	mariadb "suglider-auth/internal/database"
	v1_routers "suglider-auth/pkg/api-server/api_v1/routers"
	"suglider-auth/pkg/rbac"
	"suglider-auth/pkg/time_convert"
)

type AuthApiSettings struct {
	Name             string
	Version          string
	SubpathPrefix    string
	TemplatePath     string
	StaticPath       string
	SessionsPath     string
	CasbinConfig     string
	CasbinTable      string
	GracefulTimeout  int
	ReadTimeout      int
	WriteTimeout     int
	MaxHeaderBytes   int
	EnablePprof      bool
	EnableRbac       bool
	CasbinCache      bool
	SessionsHttpOnly bool
}

type CasbinEnforcerConfig = rbac.CasbinEnforcerConfig

func (aa *AuthApiSettings) SetupRouter(swag gin.HandlerFunc) *gin.Engine {
	router := gin.New()

	enableCors := configs.ApplicationConfig.Server.EnableCors

	// CORS setting
	if enableCors {
		slog.Info("The API server CORS feature is enabled.")
		router.Use(corsMiddleware())
	} else {
		slog.Info("The API server CORS feature is disabled.")
	}

	router.Use(gin.Logger())

	cookieStore := cookie.NewStore([]byte("suglider"))
	router.Use(sessions.Sessions("session-key", cookieStore))

	// Set session expire time
	_, cookieMaxAge, _ := time_convert.ConvertTimeFormat(configs.ApplicationConfig.Session.Timeout)
	cookieStore.Options(sessions.Options{
		MaxAge:   cookieMaxAge, // unit second
		HttpOnly: aa.SessionsHttpOnly,
		Path:     aa.SessionsPath,
	})

	if aa.EnablePprof {
		pprof.Register(router, aa.SubpathPrefix+"debug/pprof")
	}
	if swag != nil {
		if aa.SubpathPrefix != "" {
			docs.SwaggerInfo.BasePath = aa.SubpathPrefix
		} else {
			docs.SwaggerInfo.BasePath = "/"
		}
		router.GET("/swagger/*any", swag)
	}
	router.GET(aa.SubpathPrefix+"/healthz", aa.healthzHandler)

	// Load HTML templates and static resources
	if aa.TemplatePath == "" {
		aa.TemplatePath = "web/template"
	}
	if aa.StaticPath == "" {
		aa.StaticPath = "web/static"
	}
	router.LoadHTMLGlob(fmt.Sprintf("%s/*", aa.TemplatePath))
	router.Static("/static", aa.StaticPath)

	// RBAC model
	csbnConf := &rbac.CasbinSettings{
		Config:      aa.CasbinConfig,
		Table:       aa.CasbinTable,
		Db:          mariadb.DataBase,
		EnableCache: aa.CasbinCache,
	}
	csbn, err := rbac.NewCasbinEnforcerConfig(csbnConf)
	if err != nil {
		slog.Error(err.Error())
	}
	if err = csbn.InitPolicies(); err != nil {
		slog.Error(err.Error())
	}

	router.Use(CheckUserJWT())

	if aa.EnableRbac {
		router.Use(userPrivilege(csbn))
	}

	apiv1Router := router.Group(aa.SubpathPrefix + "/api/v1")
	{
		v1_routers.Apiv1Handler(apiv1Router, csbn)
	}

	return router
}

func corsMiddleware() gin.HandlerFunc {

	corsCredentials := configs.ApplicationConfig.Server.CorsCredentials
	corsOrigin := configs.ApplicationConfig.Server.CorsOrigin
	corsMethods := configs.ApplicationConfig.Server.CorsMethods
	corsHeaders := configs.ApplicationConfig.Server.CorsHeaders

	slog.Info(fmt.Sprintf("cors_credentials = %v", corsCredentials))
	slog.Info(fmt.Sprintf("cors_origin = %s", corsOrigin))

	if corsCredentials && corsOrigin == "*" {
		slog.Error("Configuration cors_origin variable can't be wildcatd(*) because cors_credentials is true")
		os.Exit(1)
	}

	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(corsCredentials))
		c.Writer.Header().Set("Access-Control-Allow-Origin", corsOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Methods", corsMethods)
		c.Writer.Header().Set("Access-Control-Allow-Headers", corsHeaders)
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	}
}

func (aa *AuthApiSettings) StartServer(addr string, swag gin.HandlerFunc) {
	router := aa.SetupRouter(swag)
	srv := &http.Server{
		Addr:           addr,
		Handler:        router,
		ReadTimeout:    time.Duration(aa.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(aa.WriteTimeout) * time.Second,
		MaxHeaderBytes: aa.MaxHeaderBytes << 20, // default is max 2 MB
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errorMessage := fmt.Sprintf("Server Listen Error: %v", err)
			slog.Error(errorMessage)

		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(aa.GracefulTimeout)*time.Second,
	)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		errorMessage := fmt.Sprintf("Server forced to shutdown: %v", err)
		slog.Error(errorMessage)
		os.Exit(1)
	}
	select {
	case <-ctx.Done():
		slog.Info("Graceful Shutdown start...")
		close(quit)
	}
	slog.Info("Graceful shutdown finished...")
}
