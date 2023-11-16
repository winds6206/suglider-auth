package pwd_validator

import (
	"github.com/go-playground/validator/v10"
	"unicode"
)

type signUpPayload struct {
	Username string `validate:"required,max=20"`
	Password string `validate:"required,min=8,max=30,passwordComplexity"`
	Mail     string `validate:"required,email"`
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

func PwdValidator(username, password, mail string) (error) {

	payload := &signUpPayload{
		Username: username,
		Password: password,
		Mail: mail,
	}

	v := validator.New()
	v.RegisterValidation("passwordComplexity", passwordComplexity)

	err := v.Struct(payload)
	if err != nil {

		return err
	}

	return nil
}