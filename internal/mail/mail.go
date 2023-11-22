package mail

import (
	"context"
	"fmt"
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
	Mail string
	Id   string
	Code string
}

func NewUserMailVerification(mail string) *UserMailVerification {
	mailVerify := UserMailVerification{Mail: mail}
	mailVerify.Id = encrypt.RandomString(12, "")
	mailVerify.Code = encrypt.HashWithSHA(fmt.Sprintf("%s_:_%s", mail, mailVerify.Id), "sha256")
	return &mailVerify
}

func (umv *UserMailVerification) Register(ctx context.Context, ttl int64) string {
	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	if ttl <= 0 {
		ttl = 24
	}
	err := rds.Set(key, umv.Code, time.Duration(ttl)*time.Hour)
	if err != nil {
		// TODO
	}

	params := url.Values{}
	params.Add("mail", umv.Mail)
	params.Add("verify-id", umv.Id)
	params.Add("verify-code", umv.Code)

	return params.Encode()
}

func (umv *UserMailVerification) Unregister(ctx context.Context) {
	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	err := rds.Delete(key)
	if err != nil {
		// TODO
	}
}

func (umv *UserMailVerification) IsVerified(ctx context.Context) bool {
	var isVerified bool
	isVerified, _ = db.UserMailIsVerified(ctx, umv.Mail)
	return isVerified
}

func (umv *UserMailVerification) Verify(ctx context.Context) (bool, error) {
	isVerified := umv.IsVerified(ctx)
	if isVerified {
		return true, fmt.Errorf("This mail already verified.")
	}
	key := fmt.Sprintf("%s/%s", umv.Mail, umv.Id)
	code, _, _ := rds.Get(key)
	switch code {
	case "":
		return false, fmt.Errorf("The verification has been expired or invalid, resend mail and try again.")
	case umv.Code:
		if err := db.UserSetMailVerified(ctx, umv.Mail); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func init() {
	mail = &smtp.SmtpMail{
		Username: configs.ApplicationConfig.Mail.Smtp.Username,
		Password: configs.ApplicationConfig.Mail.Smtp.Password,
		From:     configs.ApplicationConfig.Mail.Smtp.Mailer,
		SmtpHost: configs.ApplicationConfig.Mail.Smtp.SmtpHost,
		SmtpPort: configs.ApplicationConfig.Mail.Smtp.SmtpPort,
		Insecure: configs.ApplicationConfig.Mail.Smtp.Insecure,
	}
	requestUrl = &smtp.RequestUrl{
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
	htmlMail = &smtp.HtmlMail{
		RequestUrl:   requestUrl,
		TemplatePath: configs.ApplicationConfig.Server.TemplatePath,
		TTL:          configs.ApplicationConfig.Mail.Expired.TTL,
	}
}

func SendVerifyMail(ctx context.Context, user, email string) error {
	umv := NewUserMailVerification(email)
	isVerified := umv.IsVerified(ctx)
	if isVerified {
		return fmt.Errorf("This mail already verified.")
	}
	params := umv.Register(ctx, htmlMail.TTL)
	tempFile := fmt.Sprintf("%s/mail-verification.tmpl", htmlMail.TemplatePath)
	cont, err := htmlMail.GenerateVerifyMail(ctx, tempFile, user, params)
	if err != nil {
		return err
	}
	if err = mail.Send(ctx, "Welcome to Suglider, please verify your email address", cont, "", email); err != nil {
		return err
	}
	return nil
}

func VerifyUserMailAddress(ctx context.Context, email, id, code string) (bool, error) {
	umv := &UserMailVerification{
		Mail: email,
		Id:   id,
		Code: code,
	}
	ok, err := umv.Verify(ctx)
	if ok && err == nil {
		umv.Unregister(ctx)
	}
	return ok, err
}

type UserResetPassword struct {
	Mail string
	Id   string
	Code string
}

func NewUserResetPassword(mail string) *UserResetPassword {
	pwdReset := UserResetPassword{Mail: mail}
	pwdReset.Id = encrypt.RandomString(12, "")
	pwdReset.Code = encrypt.HashWithSHA(fmt.Sprintf("%s::_::%s", mail, pwdReset.Id), "sha512")
	return &pwdReset
}

func (urp *UserResetPassword) Register(ctx context.Context, ttl int64) string {
	key := fmt.Sprintf("%s/%s", urp.Mail, urp.Id)
	if ttl <= 0 {
		ttl = 24
	}
	err := rds.Set(key, urp.Code, time.Duration(ttl)*time.Hour)
	if err != nil {
		// TODO
	}

	params := url.Values{}
	params.Add("mail", urp.Mail)
	params.Add("reset-id", urp.Id)
	params.Add("reset-code", urp.Code)

	return params.Encode()
}

func (urp *UserResetPassword) Unregister(ctx context.Context) {
	key := fmt.Sprintf("%s/%s", urp.Mail, urp.Id)
	err := rds.Delete(key)
	if err != nil {
		// TODO
	}

}

func (urp *UserResetPassword) Verify(ctx context.Context) (bool, error) {
	key := fmt.Sprintf("%s/%s", urp.Mail, urp.Id)
	code, _, _ := rds.Get(key)
	switch code {
	case "":
		return false, fmt.Errorf("The verification has been expired or invalid, resend mail and try again.")
	case urp.Code:
		return true, nil
	}
	return false, nil
}

func SendPasswordResetMail(ctx context.Context, email string) error {
	urp := NewUserResetPassword(email)
	user, err := db.UserGetNameByMail(ctx, email)
	if err != nil {
		return err
	}
	params := urp.Register(ctx, htmlMail.TTL)
	tempFile := fmt.Sprintf("%s/forgot-password.tmpl", htmlMail.TemplatePath)
	cont, err := htmlMail.GenerateForgotPasswordMail(ctx, tempFile, user, params)
	if err != nil {
		return err
	}
	if err = mail.Send(ctx, "Suglider Password Reset", cont, "", email); err != nil {
		return err
	}
	return nil
}

func CheckPasswordResetCode(ctx context.Context, email, id, code string) (bool, error) {
	urp := &UserResetPassword{
		Mail: email,
		Id:   id,
		Code: code,
	}
	ok, err := urp.Verify(ctx)
	if ok && err == nil {
		urp.Unregister(ctx)
	}
	return ok, err
}

func SendMailOTP(ctx context.Context, username, email, code string) error {
	tempFile := fmt.Sprintf("%s/mail-otp.tmpl", htmlMail.TemplatePath)
	cont, err := htmlMail.GenerateOTPmail(ctx, code, username, tempFile)
	if err != nil {
		return err
	}

	errSend := mail.Send(ctx, "Suglider account OTP", cont, "", email)
	if errSend != nil {
		return errSend
	}

	return nil
}
