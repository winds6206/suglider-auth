package main

import (
	"fmt"
	"log"
	"os"
	"io"
	"github.com/gin-gonic/gin"

	sqltable "suglider-auth/init/sql_table"
	mariadb "suglider-auth/internal/database/connect"
	"suglider-auth/configs"
	"suglider-auth/pkg/api-server"
)

type (
	authApiSettings = api_server.AuthApiSettings
)

const ServiceName string = "Suglider-Auth"

var (
	Version           string
	Build             string
	swag              gin.HandlerFunc
)

// @title                      Suglider-Auth API Doc
// @version                    1.0
// @description                API Doc for Suglider Auth
// @termsOfService             http://swagger.io/terms/
// @contact.name               Above&Beyond
// @contact.email              geek@openmind.np
// @license.name               MIT
// @license.url                https://github.com/tony/suglider-auth/blob/master/LICENSE
// @schemes                    http https
// @BasePath                   /
// @securityDefinitions.apikey BearerAuth
// @in                         header
// @name                       Authorization
// @securityDefinitions.apikey ApiKeyAuth
// @in                         header
// @name                       X-API-KEY

func init() {
	srvName := fmt.Sprintf("[%s]", ServiceName)
	log.SetPrefix(srvName)
	log.SetFlags(log.LstdFlags|log.Lshortfile)

	if configs.ApplicationConfig.Log.Filelog.Filename == "" {
		configs.ApplicationConfig.Log.Filelog.Filename = fmt.Sprintf("/var/log/%s/%s.log", ServiceName, ServiceName)
	}

	flog := configs.ApplicationConfig.Log.Filelog
	mw := io.MultiWriter(os.Stdout, flog)

	if configs.Args.Syslog {
		logger, err := configs.ApplicationConfig.Log.Syslog.CreateSyslogLogger(srvName)
		if err != nil {
			log.Printf("Remote or local syslog server error: %v\n", err)
		} else {
			mlw := io.MultiWriter(os.Stdout, flog, logger)
			log.SetOutput(mlw)
		}
	}
	log.SetOutput(mw)

	sqltable.SugliderTableInit()
}

func main() {
	apiServer := &authApiSettings {
		Name:            ServiceName,
		Version:         Version,
		GracefulTimeout: configs.ApplicationConfig.Server.GracefulTimeout,
		ReadTimeout:     configs.ApplicationConfig.Server.ReadTimeout,
		WriteTimeout:    configs.ApplicationConfig.Server.WriteTimeout,
		MaxHeaderBytes:  configs.ApplicationConfig.Server.MaxHeaderBytes,
		EnablePprof:     configs.Args.Debug,
	}

	if configs.Args.Subpath != "" {
		apiServer.SubpathPrefix = configs.Args.Subpath
	}

	fmt.Printf("[%s] Version:    %s\n", ServiceName, Version)
	fmt.Printf("[%s] Build Date: %s\n", ServiceName, Build)

	addr := fmt.Sprintf("%s:%d", configs.Args.Host, configs.Args.Port)
	apiServer.StartServer(addr, swag)

	mariadb.Close()
}
