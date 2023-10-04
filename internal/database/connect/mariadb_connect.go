package mariadb

import (
	"log"
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"suglider-auth/configs"
)

var SugliderDB *sqlx.DB

func init() {

	var dbErr error

	var DatabaseConfig = configs.ApplicationConfig.Database

	// DB connection setting
	dbConfig := mysql.Config{
		User:      DatabaseConfig.User,
		Passwd:    DatabaseConfig.Password,
		Net:       "tcp",
		Addr:      DatabaseConfig.Host + ":" + DatabaseConfig.Port,
		DBName:    DatabaseConfig.Name,
		AllowNativePasswords: true,
	}

	// Generate MariaDB connection string
	SugliderDBURL := dbConfig.FormatDSN()

	// Connect to MariaDB
	SugliderDB, dbErr = sqlx.Connect("mysql", SugliderDBURL)
	if dbErr != nil {
		log.Println("Can not connect to database:", dbErr)
		panic(dbErr)
	}

	// Set DB max connection
    SugliderDB.DB.SetMaxOpenConns(100)

	log.Println("Connected to SugliderDB successfully！")

}

// Close DB connection
func Close() {
	SugliderDB.Close()
	return
}
