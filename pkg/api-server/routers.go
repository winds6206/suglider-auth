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
	v1_routers "suglider-auth/pkg/api-server/api_v1/routers"

	docs "suglider-auth/docs"
)

type AuthApiSettings struct {
	Name            string
	Version         string
	SubpathPrefix   string
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

	apiv1Router := router.Group("/api/v1")
	{
		v1_routers.Apiv1Handler(apiv1Router)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
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