package pwd_validator

import (
	"github.com/go-playground/validator/v10"
	"fmt"
)

type signUpPayload struct {
	Username string `validate:"required,max=20"`
	Password string `validate:"required,min=8,max=20"`
	Mail     string `validate:"required,email"`
}

func PwdValidator(username, password, mail string) (error) {

	payload := &signUpPayload{
		Username: username,
		Password: password,
		Mail: mail,
	}

	v := validator.New()

	err := v.Struct(payload)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}