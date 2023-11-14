package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/smtp"
	"text/template"
	"gopkg.in/gomail.v2"
)

type SmtpMail struct {
	Username  string // same as From if use gmail smtp
	Password  string
	From      string
	SmtpHost  string
	SmtpPort  int
	Insecure  bool
}

func (sm *SmtpMail) Send(ctx context.Context, sub, cont, file string, to ...string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", sm.From)
	msg.SetHeader("To", to...)
	msg.SetHeader("Subject", sub)
	msg.SetBody("text/html", cont)
	if file != "" {
		msg.Attach(file)
	}

	d := gomail.NewDialer(sm.SmtpHost, sm.SmtpPort, sm.Username, sm.Password)
	d.TLSConfig = &tls.Config {
		InsecureSkipVerify: sm.Insecure,
		ServerName:         sm.SmtpHost,
	}

	if err := d.DialAndSend(msg); err != nil {
		return err
	}
	return nil
}

func (sm *SmtpMail) SendX(ctx context.Context, sub, cont string, to ...string) error {
	smtpAddress := fmt.Sprintf("%s:%d", sm.SmtpHost, sm.SmtpPort)
	subject := fmt.Sprintf("Subject: %s", sub)
	message := []byte(fmt.Sprintf("%s\n%s", subject, cont))

	auth := smtp.PlainAuth("", sm.Username, sm.Password, sm.SmtpHost)
	if err := smtp.SendMail(smtpAddress, auth, sm.From, to, message); err != nil {
		return err
	}
	return nil
}

type RequestUrl struct {
	Url   string
	Path  string
}

type HtmlMail struct {
	TemplatePath  string
	RequestUrl    *RequestUrl
	TTL           int64
}

type MailVerifyReplace struct {
	Name        string
	Url         string
	Uri         string
	QueryParams string
}

func (hm *HtmlMail) GenerateVerifyMail(ctx context.Context, tempFile, userName, queryParams string) (string, error) {
	tmplFile, err := ioutil.ReadFile(tempFile)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New("htmlMail").Parse(string(tmplFile))
	if err != nil {
		return "", err
	}
	replaceContent := MailVerifyReplace {
		Name:        userName,
		Url:         hm.RequestUrl.Url,
		Uri:         fmt.Sprintf("%s%s", hm.RequestUrl.Path, "/user/verify-mail"),
		QueryParams: queryParams,
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, replaceContent); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (hm *HtmlMail) GenerateForgotPasswordMail(ctx context.Context, tempFile, userName, queryParams string) (string, error) {
	tmplFile, err := ioutil.ReadFile(tempFile)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New("htmlMail").Parse(string(tmplFile))
	if err != nil {
		return "", err
	}
	replaceContent := MailVerifyReplace {
		Name:        userName,
		Url:         hm.RequestUrl.Url,
		Uri:         fmt.Sprintf("%s%s", hm.RequestUrl.Path, "/user/forgot-password"),
		QueryParams: queryParams,
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, replaceContent); err != nil {
		return "", err
	}
	return buf.String(), nil
}
