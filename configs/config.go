package configs

import (
	"flag"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"

	"github.com/BurntSushi/toml"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	ApplicationConfig Config
	Args              *Arguments
)

type Arguments struct {
	Host    string
	Config  string
	Subpath string
	Port    int
	Syslog  bool
	Debug   bool
}

type (
	Config struct {
		Database *Database        `toml:"database"`
		Redis    *Redis           `toml:"redis"`
		Session  *Session         `toml:"session"`
		Server   *serverSettings  `toml:"server"`
		Log      *logSettings     `toml:"log"`
		Swagger  *swaggerSettings `toml:"swagger"`
		Mail     *mailSettings    `toml:"mail"`
		Oauth    *Oauth           `toml:"oauth"`
	}
	Database struct {
		Host       string `toml:"host"`
		Port       string `toml:"port"`
		Name       string `toml:"name"`
		User       string `toml:"user"`
		Password   string `toml:"password"`
		Timeout    string `toml:"timeout"`
		SyntaxPath string `toml:"syntax_path"`
	}
	Redis struct {
		Host     string `toml:"host"`
		Port     string `toml:"port"`
		Password string `toml:"password"`
	}
	Session struct {
		Timeout  string `toml:"timeout"`
		Path     string `toml:"path"`
		HttpOnly bool   `toml:"http_only"`
	}
	serverSettings struct {
		TemplatePath    string `toml:"template_path"`
		StaticPath      string `toml:"static_path"`
		SwaggerPath     string `toml:"swagger_path"`
		CasbinConfig    string `toml:"casbin_config"`
		CasbinTable     string `toml:"casbin_table"`
		GracefulTimeout int    `toml:"graceful_timeout"`
		ReadTimeout     int    `toml:"read_timeout"`
		WriteTimeout    int    `toml:"write_timeout"`
		MaxHeaderBytes  int    `toml:"max_header_bytes"`
		EnableRbac      bool   `toml:"enable_rbac"`
		EnableCors      bool   `toml:"enable_cors"`
		CorsCredentials bool   `toml:"cors_credentials"`
		CorsOrigin      string `toml:"cors_origin"`
		CorsMethods     string `toml:"cors_methods"`
		CorsHeaders     string `toml:"cors_headers"`
		CasbinCache     bool   `toml:"casbin_cache"`
	}
	logSettings struct {
		Filelog *lumberjack.Logger `toml:"filelog"`
		Syslog  *syslogSettings    `toml:"syslog"`
	}
	syslogSettings struct {
		Protocol string `toml:"protocol"`
		Host     string `toml:"host"`
		Port     int    `toml:"port"`
	}
	swaggerSettings struct {
		Theme string `toml:"theme"`
	}
	mailSettings struct {
		Smtp        *smtpSettings `toml:"smtp"`
		FrontendUrl *frontendUrl  `toml:"frontend_url"`
		Expired     *mailExpired  `toml:"expired"`
	}
	smtpSettings struct {
		Username string `toml:"username"`
		Password string `toml:"password"`
		Mailer   string `toml:"mailer"`
		SmtpHost string `toml:"smtp_host"`
		SmtpPort int    `toml:"smtp_port"`
		Insecure bool   `toml:"smtp_insecure"`
	}
	frontendUrl struct {
		Scheme     string `toml:"scheme"`
		Domain     string `toml:"domain"`
		PathPrefix string `toml:"path_prefix"`
		Port       int    `toml:"port"`
	}
	mailExpired struct {
		TTL int64 `toml:"ttl"`
	}

	Oauth struct {
		Google Google `toml:"google"`
	}

	Google struct {
		ClientID     string `toml:"client_id"`
		ClientSecret string `toml:"client_secret"`
	}
)

func parseFlags() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.Host, "host", "0.0.0.0", "The ip or hostname of this server, default is 0.0.0.0.")
	flag.StringVar(&args.Host, "h", "0.0.0.0", "The ip or hostname of this server, default is 0.0.0.0. (shorten)")
	flag.IntVar(&args.Port, "port", 9527, "The port to serve.")
	flag.IntVar(&args.Port, "p", 9527, "The port to serve, default is 9527. (shorten)")
	flag.StringVar(&args.Subpath, "subpath", "/", "The subpath prefix of server, default is / as root path.")
	flag.StringVar(&args.Subpath, "a", "/", "The subpath prefix of server, default is / as root path. (shorten)")
	flag.StringVar(&args.Config, "config", "", "The config with toml format for this server.")
	flag.StringVar(&args.Config, "c", "", "The config with toml format for this server. (shorten)")
	flag.BoolVar(&args.Syslog, "syslog", false, "Enable logging uses syslog protocol.")
	flag.BoolVar(&args.Syslog, "s", false, "Enable logging uses syslog protocol. (shorten)")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug mode which use pprof to analyze program.")
	flag.BoolVar(&args.Debug, "d", false, "Enable debug mode which use pprof to analyze program (shorten).")
	flag.Parse()
	return args
}

func loadConfig() {
	Args = parseFlags()
	if Args.Config == "" {
		// Database
		ApplicationConfig.Database.Host = os.Getenv("DB_HOST")
		ApplicationConfig.Database.Port = os.Getenv("DB_PORT")
		ApplicationConfig.Database.Name = os.Getenv("DB_NAME")
		ApplicationConfig.Database.User = os.Getenv("DB_USER")
		ApplicationConfig.Database.Password = os.Getenv("DB_PASSWORD")
		ApplicationConfig.Database.Timeout = os.Getenv("DB_TIMEOUT")

		// Redis
		ApplicationConfig.Redis.Host = os.Getenv("Redis_HOST")
		ApplicationConfig.Redis.Port = os.Getenv("Redis_PORT")

		// Session
		ApplicationConfig.Redis.Host = os.Getenv("Session_TIMEOUT")

		// OAuth Google
		ApplicationConfig.Oauth.Google.ClientID = os.Getenv("Google_Client_ID")
		ApplicationConfig.Oauth.Google.ClientSecret = os.Getenv("Google_Client_Secret")
	} else {
		_, err := toml.DecodeFile(Args.Config, &ApplicationConfig)
		if err != nil {
			errorMessage := fmt.Sprintf("Failed to load the configuration: %v", err)
			slog.Error(errorMessage)
			panic(err)
		}
	}
}

func (l *syslogSettings) CreateSyslogLogger(name string) (*syslog.Writer, error) {
	var hostAddr string

	if l.Protocol == "" {
		l.Protocol = "udp"
	}
	if l.Port == 0 {
		l.Port = 514
	}
	if l.Host == "" {
		l.Host = "locahost"
	}
	hostAddr = fmt.Sprintf("%s:%d", l.Host, l.Port)

	logger, err := syslog.Dial(l.Protocol, hostAddr, syslog.LOG_ERR|syslog.LOG_DAEMON, name)
	if err != nil {
		errorMessage := fmt.Sprintf("Syslog Server Error: %v", err)
		slog.Error(errorMessage)

		return nil, err
	}

	return logger, err
}

func init() {
	loadConfig()
}
