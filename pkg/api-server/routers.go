package api_server

import (
	"os"
	"os/signal"
	"syscall"
	"time"
	"context"
	"net/http"
	"log"
	"log/slog"
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/casbin/casbin/v2"
	"github.com/memwey/casbin-sqlx-adapter"

	v1_routers "suglider-auth/pkg/api-server/api_v1/routers"
	docs "suglider-auth/docs"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/pkg/time_convert"
)

type AuthApiSettings struct {
	Name            string
	Version         string
	SubpathPrefix   string
	CasbinConfig    string
	CasbinTable     string
	GracefulTimeout int
	ReadTimeout     int
	WriteTimeout    int
	MaxHeaderBytes  int
	EnablePprof     bool
}

type CasbinConfig = v1_routers.CasbinConfig

func (aa * AuthApiSettings) SetupRouter(swag gin.HandlerFunc) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())

	cookieStore := cookie.NewStore([]byte("suglider"))
	router.Use(sessions.Sessions("session-key", cookieStore))

	// Set session expire time
	// time_convert.CookieMaxAge is a global variable from time_convert.go
	cookieStore.Options(sessions.Options{
		MaxAge:   time_convert.CookieMaxAge,  // unit second
		HttpOnly: true,
	})

	if aa.EnablePprof {
		pprof.Register(router, aa.SubpathPrefix + "debug/pprof")
	}
	if swag != nil {
		if aa.SubpathPrefix != "" {
			docs.SwaggerInfo.BasePath = aa.SubpathPrefix
		} else {
			docs.SwaggerInfo.BasePath = "/"
		}
		router.GET("/swagger/*any", swag)
	}
	router.GET(aa.SubpathPrefix + "/healthz", aa.healthzHandler)

	// RBAC model
	csbnAdapterOpts := &sqlxadapter.AdapterOptions {
		DB:        mariadb.DataBase,
		TableName: aa.CasbinTable,
		// DriverName:     "mysql",
		// DataSourceName: "root:1234@tcp(127.0.0.1:3306)/suglider",
	}
	csbnAdapter := sqlxadapter.NewAdapterFromOptions(csbnAdapterOpts)
	csbnEnforcer, err := casbin.NewEnforcer(aa.CasbinConfig, csbnAdapter)
	if err != nil {
		slog.Error(err.Error())
	}
	if ok, err := csbnEnforcer.AddPolicy("admin", "/*", "*"); !ok {
		if err != nil {
			slog.Error(err.Error())
		}
		slog.Info("This policy already exists.")
	}
	if ok, err := csbnEnforcer.AddPolicy("anonymous", "/login", "POST"); !ok {
		if err != nil {
			slog.Error(err.Error())
		}
		slog.Info("This policy already exists.")
	}
	if ok, err := csbnEnforcer.AddPolicy("anonymous", "/logout", "POST"); !ok {
		if err != nil {
			slog.Error(err.Error())
		}
		slog.Info("This policy already exists.")
	}
	if err = csbnEnforcer.LoadPolicy(); err != nil {
		slog.Error(err.Error())
		panic(err)
	}
	csbnEnforcer.EnableAutoSave(true)
	csbnConfig := &CasbinConfig {
		Enforcer:    csbnEnforcer,
		CasbinTable: aa.CasbinTable,
	}

	apiv1Router := router.Group(aa.SubpathPrefix + "/api/v1")
	{
		v1_routers.Apiv1Handler(apiv1Router, csbnConfig)
	}

	return router
}

func (aa * AuthApiSettings) StartServer(addr string, swag gin.HandlerFunc) {
	router := aa.SetupRouter(swag)
	srv := &http.Server {
		Addr:           addr,
		Handler:        router,
		ReadTimeout:    time.Duration(aa.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(aa.WriteTimeout) * time.Second,
		MaxHeaderBytes: aa.MaxHeaderBytes << 20, // default is max 2 MB
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
		    log.Printf("Server Listen Error: %s\n", err)
		}
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(aa.GracefulTimeout) * time.Second,
	)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown: ", err)
		os.Exit(1)
	}
	select {
		case <-ctx.Done():
			log.Println("Graceful Shutdown start...")
			close(quit)
	}
	log.Println("Graceful shutdown finished...")
}