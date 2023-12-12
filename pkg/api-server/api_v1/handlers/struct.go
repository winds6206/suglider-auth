package handlers

type otpData struct {
	Mail    string `json:"mail" binding:"required"`
	OTPCode string `json:"otp_code" binding:"required"`
}

type oAuthResponse struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Verified   bool   `json:"verified_email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	Locale     string `json:"locale"`
}

type userSignUp struct {
	Mail        string  `json:"mail" binding:"required"`
	Password    string  `json:"password" binding:"required"`
	UserName    *string `json:"username"`
	FirstName   *string `json:"first_name"`
	LastName    *string `json:"last_name"`
	PhoneNumber *string `json:"phone_number"`
}

type userLogin struct {
	Account  string `json:"account" binding:"required"`
	Password string `json:"password"`
}

type userNameOperate struct {
	UserName string `json:"username" binding:"required"`
}

type mailOperate struct {
	Mail string `json:"mail" binding:"required"`
}

type resetPassword struct {
	Mail        string `json:"mail" binding:"required"`
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type setUpPassword struct {
	Mail     string `json:"mail" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type updatePersonalInfo struct {
	Mail        string  `json:"mail" binding:"required"`
	UserName    *string `json:"username"`
	FirstName   *string `json:"first_name"`
	LastName    *string `json:"last_name"`
	PhoneNumber *string `json:"phone_number"`
	Address     *string `json:"address"`
	Birthday    *string `json:"birthday"`
	Sex         *string `json:"sex"`
	BloodType   *string `json:"blood_type"`
}

type passwordReset struct {
	Password string `json:"password"`
}

type rdsValeData struct {
	Mail           string `json:"mail"`
	AccountPassed  bool   `json:"account_passed"`
	TotpEnabled    bool   `json:"totp_enabled"`
	MailOTPEnabled bool   `json:"mail_otp_enabled"`
	SmsOTPEnabled  bool   `json:"sms_otp_enabled"`
}
