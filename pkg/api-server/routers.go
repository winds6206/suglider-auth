package api_server

import (
	"os"
	"os/signal"
	"syscall"
	"time"
	"context"
	"net/http"
	"log"
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/pprof"

	docs "suglider-auth/docs"
)

type AuthApiSettings struct {
	Name            string
	Version         string
	SubpathPrefix   string
	GracefulTimeout int
	ReadTimeout     int
	WriteTimeout    int
	MaxHeaderBytes  int
	EnablePprof     bool
}

func (aa * AuthApiSettings) SetupRouter(swag gin.HandlerFunc) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	if aa.EnablePprof {
		pprof.Register(router, "debug/pprof")
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

	if aa.GracefulTimeout <= 0 { aa.GracefulTimeout = 5 }

	go func() {
		if err := srv.ListenAndServe(); err != nil {
		    log.Printf("Server Listen Error: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	// run kill -2 <pid> (SIGINT) to stop gracefully (same as trigger by Ctrl-C)
	// run kill -1 <pid> (SIGHUP) to restart gracefully
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
			log.Printf("timeout of %d seconds.\n", aa.GracefulTimeout)
			close(quit)
	}
	log.Println("Server exiting")
}
