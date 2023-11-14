package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	smtp "suglider-auth/pkg/mail"
)

var (
	params  *args
)

type args struct {
	Username   string
	Passowrd   string
	Subtile    string
	File       string
	Attach     string
	From       string
	To         string
	SmtpHost   string
	SmtpPort   int
	Insecure   bool
}

func parseArgs() *args {
	settings := &args{}
	flag.StringVar(&settings.SmtpHost, "host", "live.smtp.mailtrap.io", "The ip or hostname of smtp server, default is live.smtp.mailtrap.io.")
	flag.StringVar(&settings.SmtpHost, "h", "live.smtp.mailtrap.io", "The ip or hostname of smtp server, default is live.smtp.mailtrap.io. (shorten)")
	flag.IntVar(&settings.SmtpPort, "port", 587, "The port of smtp server, default is 587.")
	flag.IntVar(&settings.SmtpPort, "p", 587, "The port of smtp server, default is 587. (shorten)")
	flag.StringVar(&settings.Username, "user", "", "The username for authentication of smtp server.")
	flag.StringVar(&settings.Username, "u", "", "The username for authentication of smtp server. (shorten)")
	flag.StringVar(&settings.Passowrd, "password", "", "The password for authentication of smtp server.")
	flag.StringVar(&settings.Passowrd, "a", "", "The password for authentication of smtp server. (shorten)")
	flag.StringVar(&settings.Attach, "attach", "", "The file to attached in the mail.")
	flag.StringVar(&settings.Attach, "T", "", "The file to attached in the mail. (shorten)")
	flag.StringVar(&settings.File, "file", "", "The file as content of mail.")
	flag.StringVar(&settings.File, "f", "", "The file as content of mail. (shorten)")
	flag.StringVar(&settings.From, "from", "", "The mailer (from) to send mail.")
	flag.StringVar(&settings.From, "m", "", "The mailer (from) to send mail. (shorten)")
	flag.StringVar(&settings.To, "to", "", "The receiver (to) of mail.")
	flag.StringVar(&settings.To, "t", "", "The receiver (to) of mail. (shorten)")
	flag.StringVar(&settings.Subtile, "subtile", "How to join the open source project", "The subtile (title) of mail.")
	flag.StringVar(&settings.Subtile, "s", "How to join the open source project", "The subtile (title) of mail. (shorten)")
	flag.BoolVar(&settings.Insecure, "insecure", false, "Enable the InsecureSkipVerify for smtp dialer.")
	flag.BoolVar(&settings.Insecure, "i", false, "Enable the InsecureSkipVerify for smtp dialer. (shorten)")
	flag.Parse()
	return settings
}

func init() {
	params = parseArgs()

	// check the required flags
	if params.Username == "" {
		fmt.Println("The '-user/-u' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.Passowrd == "" {
		fmt.Println("The '-password/-a' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.From == "" {
		fmt.Println("The '-from/-a' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.To == "" {
		fmt.Println("The '-to/-t' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.File == "" {
		fmt.Println("The '-file/-f' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.Subtile == "" {
		fmt.Println("The '-subtile/-s' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
}

func main() {
	ctx := context.TODO()
	smtp := &smtp.SmtpMail {
		SmtpHost: params.SmtpHost,
		SmtpPort: params.SmtpPort,
		From:     params.From,
		Username: params.Username,
		Password: params.Passowrd,
		Insecure: params.Insecure,
	}

	message, err := ioutil.ReadFile(params.File)
	if err != nil {
		panic(err)
	}

	if err := smtp.Send(ctx, params.Subtile, string(message), params.Attach, params.To); err != nil {
		fmt.Printf("Fail to send mail: %v\n", err)
		return
	}

	fmt.Println("Send mail successfully.")
}
