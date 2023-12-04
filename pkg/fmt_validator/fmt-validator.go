package fmt_validator

import (
	"regexp"
	"unicode"

	"github.com/go-playground/validator/v10"
)

type signUpPayload struct {
	Mail     string `validate:"required,email"`
	Username string `validate:"max=20"`
	Password string `validate:"required,min=8,max=30,passwordComplexity"`
}

type mailData struct {
	Mail string `validate:"required,email"`
}

type phoneData struct {
	PhoneNumber string `validate:"max=10,phoneNumberCheck"`
}

type passwordData struct {
	Password string `validate:"required,min=8,max=30,passwordComplexity"`
}

func passwordComplexity(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	hasUpperCase := false
	hasLowerCase := false
	hasNumber := false
	hasSpecialChar := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpperCase = true
		case unicode.IsLower(char):
			hasLowerCase = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecialChar = true
		}
	}

	return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar
}

func phoneNumberCheck(fl validator.FieldLevel) bool {
	phoneNumber := fl.Field().String()

	if phoneNumber == "" {
		return true
	}

	matched, _ := regexp.MatchString(`^\d+$`, phoneNumber)

	if !matched {
		return matched // this block matched will be "false"
	}

	return true
}

func PwdValidator(userName, password, mail string) error {

	payload := &signUpPayload{
		Username: userName,
		Password: password,
		Mail:     mail,
	}

	v := validator.New()
	v.RegisterValidation("passwordComplexity", passwordComplexity)

	err := v.Struct(payload)
	if err != nil {

		return err
	}

	return nil
}

func FmtValidator(mail, password string) error {

	payload := &signUpPayload{
		Mail:     mail,
		Password: password,
	}

	v := validator.New()
	v.RegisterValidation("passwordComplexity", passwordComplexity)

	err := v.Struct(payload)
	if err != nil {

		return err
	}

	return nil
}

func MailValidator(mail string) bool {

	payload := &mailData{
		Mail: mail,
	}

	v := validator.New()

	err := v.Struct(payload)
	if err != nil {
		return false
	}

	return true
}

func PhoneNumberValidator(phoneNumber *string) bool {

	payload := &phoneData{
		PhoneNumber: *phoneNumber,
	}

	v := validator.New()
	v.RegisterValidation("phoneNumberCheck", phoneNumberCheck)

	err := v.Struct(payload)
	if err != nil {
		return false
	}

	return true
}

func PasswordValidator(password string) bool {

	payload := &passwordData{
		Password: password,
	}

	v := validator.New()
	v.RegisterValidation("passwordComplexity", passwordComplexity)

	err := v.Struct(payload)
	if err != nil {
		return false
	}

	return true
}
