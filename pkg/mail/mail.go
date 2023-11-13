package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/url"
	"text/template"
	"time"
	"gopkg.in/gomail.v2"

	db "suglider-auth/internal/database"
	rds "suglider-auth/internal/redis"
	"suglider-auth/pkg/encrypt"
)

type ApiUrl struct {
	Url   string
	Path  string
}

type HtmlMail struct {
	TemplatePath  string
	ApiUrl        *ApiUrl
}

type MailVerifyReplace struct {
	Name        string
	Url         string
	Uri         string
	QueryParams string
}

func (hm *HtmlMail) GenerateVerifyMail(ctx context.Context, userName, queryParams string) (string, error) {
	tmplFile, err := ioutil.ReadFile(fmt.Sprintf("%s/mail-verification.tmpl", hm.TemplatePath))
	if err != nil {
		return "", err
	}
	tmpl, err := template.New("htmlMail").Parse(string(tmplFile))
	if err != nil {
		return "", err
	}
	replaceContent := MailVerifyReplace {
		Name:        userName,
		Url:         hm.ApiUrl.Url,
		Uri:         fmt.Sprintf("", hm.ApiUrl.Path, "/user/verify-mail"),
		QueryParams: queryParams,
	}
	buf := new(bytes.Buffer)
	if err = tmpl.Execute(buf, replaceContent); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (hm *HtmlMail) GenerateResetPasswordMail(ctx context.Context, userName, queryParams string) (string, error) {
	return "", nil
}

type SmtpMail struct {
	Username  string // same as From if use gmail smtp
	Password  string
	From      string
	SmtpHost  string
	SmtpPort  int
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
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(msg); err != nil {
		return err
	}
	return nil
}

type UserMailVerification struct {
	Mail  string
	Id    string
	Code  string
	TTL   int
}

func NewUserMailVerification(mail string) *UserMailVerification {
	mailVerify := UserMailVerification { Mail: mail }
	mailVerify.Id = encrypt.RandomString(12, "")
	mailVerify.Code = encrypt.HashWithSHA(fmt.Sprintf("%s_:_%s", mail, mailVerify.Id), "sha256")
	return &mailVerify
}

func (umv *UserMailVerification) Register(ctx context.Context) string {
	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	if umv.TTL <= 0 {
		umv.TTL = 24
	}
	rds.Set(key, umv.Code, time.Duration(umv.TTL) * time.Hour)

	params := url.Values{}
	params.Add("mail", umv.Mail)
	params.Add("verify-id", umv.Id)
	params.Add("verify-code", umv.Code)

	return params.Encode()
}

func (umv *UserMailVerification) Unregister(ctx context.Context) {
	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	rds.Delete(key)
}

func (umv *UserMailVerification) Verify(ctx context.Context) (bool, error) {
	var isVerified int
	query := fmt.Sprintf("SELECT mail_verified FROM %s WHERE %s = ?", "user_info", "mail")
	row := db.DataBase.DB.QueryRowContext(ctx, query, umv.Mail)
	if err := row.Scan(&isVerified); err != nil {
		return false, err
	}
	if isVerified == 1 {
		return true, fmt.Errorf("This mail already verified.")
	}

	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	code := rds.Get(key)
	switch code {
	case "":
		return false, fmt.Errorf("The verification has been expired, resend mail and try again.")
	case umv.Code:
		statmt := fmt.Sprintf("UPDATE %s SET mail_verified = ? WHERE %s = ?", "user_info", "mail")
		if _, err := db.DataBase.DB.ExecContext(ctx, statmt, 1, umv.Mail); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
