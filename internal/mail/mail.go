package mail

import (
	"context"
	"fmt"
	"suglider-auth/configs"
	smtp "suglider-auth/pkg/mail"
)

var (
	mail     *smtp.SmtpMail
	apiUrl   *smtp.ApiUrl
	htmlMail *smtp.HtmlMail
)

func init() {
	mail = &smtp.SmtpMail {
		Username: configs.ApplicationConfig.Mail.Smtp.Username,
		Password: configs.ApplicationConfig.Mail.Smtp.Password,
		From:     configs.ApplicationConfig.Mail.Smtp.Mailer,
		SmtpHost: configs.ApplicationConfig.Mail.Smtp.SmtpHost,
		SmtpPort: configs.ApplicationConfig.Mail.Smtp.SmtpPort,
	}
	apiUrl = &smtp.ApiUrl {
		Url:  fmt.Sprintf("http://%s:%d", configs.ApplicationConfig.Server.Domain, configs.Args.Port),
		Path: "/api/v1",
	}
	htmlMail = &smtp.HtmlMail {
		ApiUrl:       apiUrl,
		TemplatePath: configs.ApplicationConfig.Server.TemplatePath,
	}
}

func SendVerifyMail(ctx context.Context, user, email string) error {
	umv := smtp.NewUserMailVerification(email)
	params := umv.Register(ctx)
	cont, err := htmlMail.GenerateVerifyMail(ctx, user, params)
	if err != nil {
		return err
	}
	if err = mail.Send(ctx, "Welcome to Suglider, please verify your email address", cont, "", email);
	err != nil {
		return err
	}
	return nil
}

func VerifyUserMail(ctx context.Context, email, id, code string) (bool, error) {
	umv := smtp.NewUserMailVerification(email)
	ok, err := umv.Verify(ctx)
	if ok && err == nil {
		umv.Unregister(ctx)
	}
	return ok, err
}
