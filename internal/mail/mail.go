package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"suglider-auth/configs"
	db "suglider-auth/internal/database"
	rds "suglider-auth/internal/redis"
	"suglider-auth/pkg/encrypt"
	smtp "suglider-auth/pkg/mail"
	"time"
)

var (
	mail       *smtp.SmtpMail
	requestUrl *smtp.RequestUrl
	htmlMail   *smtp.HtmlMail
)

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

func (umv *UserMailVerification) IsVerified(ctx context.Context) bool {
	var isVerified int
	query := fmt.Sprintf("SELECT mail_verified FROM %s WHERE %s = ?", "user_info", "mail")
	row := db.DataBase.DB.QueryRowContext(ctx, query, umv.Mail)
	if err := row.Scan(&isVerified); err != nil {
		slog.Error(err.Error())
	}
	if isVerified == 1 {
		return true
	}
	return false
}

func (umv *UserMailVerification) Verify(ctx context.Context) (bool, error) {
	isVerified := umv.IsVerified(ctx)
	if isVerified {
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

func init() {
	mail = &smtp.SmtpMail {
		Username: configs.ApplicationConfig.Mail.Smtp.Username,
		Password: configs.ApplicationConfig.Mail.Smtp.Password,
		From:     configs.ApplicationConfig.Mail.Smtp.Mailer,
		SmtpHost: configs.ApplicationConfig.Mail.Smtp.SmtpHost,
		SmtpPort: configs.ApplicationConfig.Mail.Smtp.SmtpPort,
		Insecure: configs.ApplicationConfig.Mail.Smtp.Insecure,
	}
	requestUrl = &smtp.RequestUrl {
		Path: configs.ApplicationConfig.Mail.FrontendUrl.PathPrefix,
	}
	if configs.ApplicationConfig.Mail.FrontendUrl.Port <= 0 {
		requestUrl.Url = fmt.Sprintf(
			"%s://%s",
			configs.ApplicationConfig.Mail.FrontendUrl.Scheme,
			configs.ApplicationConfig.Mail.FrontendUrl.Domain,
		)
	} else {
		requestUrl.Url = fmt.Sprintf(
			"%s://%s:%d",
			configs.ApplicationConfig.Mail.FrontendUrl.Scheme,
			configs.ApplicationConfig.Mail.FrontendUrl.Domain,
			configs.ApplicationConfig.Mail.FrontendUrl.Port,
		)
	}
	htmlMail = &smtp.HtmlMail {
		RequestUrl:   requestUrl,
		TemplatePath: configs.ApplicationConfig.Server.TemplatePath,
	}
}

func SendVerifyMail(ctx context.Context, user, email string) error {
	umv := NewUserMailVerification(email)
	isVerified := umv.IsVerified(ctx)
	if isVerified {
		return fmt.Errorf("This mail already verified.")
	}
	params := umv.Register(ctx)
	tempFile := fmt.Sprintf("%s/mail-verification.tmpl", htmlMail.TemplatePath)
	cont, err := htmlMail.GenerateVerifyMail(ctx, tempFile, user, params)
	if err != nil {
		return err
	}
	if err = mail.Send(ctx, "Welcome to Suglider, please verify your email address", cont, "", email);
	err != nil {
		return err
	}
	return nil
}

func VerifyUserMailAddress(ctx context.Context, email, id, code string) (bool, error) {
	umv := &UserMailVerification {
		Mail: email,
		Id: id,
		Code: code,
	}
	ok, err := umv.Verify(ctx)
	if ok && err == nil {
		umv.Unregister(ctx)
	}
	return ok, err
}
