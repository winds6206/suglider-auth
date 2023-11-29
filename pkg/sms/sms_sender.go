package sms

type SmsSender interface {
	Send(data interface{}) (string, error)
	SendQuery(data interface{}) (string, error)
	SendCancelSms(data interface{}) error
	Check() (bool, error)
}

type SmsClient struct {
	Sender       SmsSender
}
