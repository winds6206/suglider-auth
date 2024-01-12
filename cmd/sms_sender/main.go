package main

import(
	"flag"
	"fmt"
	"os"
	pn "github.com/nyaruka/phonenumbers"
	sms "suglider-auth/pkg/sms"
)

var (
	params  *args
)

type args struct {
	SmsIsp            string
	SmsType           string
	Username          string
	Password          string
	Message           string
	MessageId         string
	MessageType       string
	PhoneNumber       string
	CountryCode       string
	SelfPhoneNumber   string
	SelfCountryCode   string
	OrderTime         string
	MessageServiceSid string
	LimitTime         int64
	Timeout           int64
	Check             bool
}

func parseArgs() *args {
	settings := &args{}
	flag.StringVar(&settings.SmsIsp, "isp", "", "The ISP to send sms messages. Support cht and twilio for now.")
	flag.StringVar(&settings.SmsIsp, "i", "", "The ISP to send sms messages. Support cht and twilio for now.(shorten)")
	flag.StringVar(&settings.SmsType, "type", "smart", "The messag type of sms to send. Default is smart.")
	flag.StringVar(&settings.SmsType, "y", "smart", "The messag type of sms to send. Default is smart. (shorten)")
	flag.StringVar(&settings.Username, "username", "", "The username/account sid for sms isp authentication.")
	flag.StringVar(&settings.Username, "u", "", "The username/account sid for sms isp authentication. (shorten)")
	flag.StringVar(&settings.Password, "password", "", "The password for sms isp authentication and should be base64 encoded.")
	flag.StringVar(&settings.Password, "p", "", "The password for sms isp authentication and should be base64 encoded. (shorten)")
	flag.StringVar(&settings.Message, "message", "", "The message to send.")
	flag.StringVar(&settings.Message, "m", "", "The message to send. (shorten)")
	flag.StringVar(&settings.MessageId, "message-id", "", "The message id to query or cancel.")
	flag.StringVar(&settings.MessageId, "d", "", "The message id to query or cancel. (shorten)")
	flag.StringVar(&settings.MessageType, "message-type", "short", "The message type to query or cancel, this could be short (default) or long.")
	flag.StringVar(&settings.MessageType, "g", "short", "The message type to query or cancel, this could be short (default) or long. (shorten)")
	flag.StringVar(&settings.MessageServiceSid, "message-service-sid", "", "The message service sid of your twilio account.")
	flag.StringVar(&settings.MessageServiceSid, "s", "", "The message service sid of your twilio account. (shorten)")
	flag.StringVar(&settings.PhoneNumber, "phone", "", "The mobile phone number that sms message will send to.")
	flag.StringVar(&settings.PhoneNumber, "n", "", "The mobile phone number that sms message will send to. (shorten)")
	flag.StringVar(&settings.CountryCode, "country", "", "The country code which phone number belongs to.")
	flag.StringVar(&settings.CountryCode, "c", "", "The country code which phone number belongs to. (shorten)")
	flag.StringVar(&settings.SelfPhoneNumber, "self-phone", "", "The mobile phone number that sms message will send from by twilio api.")
	flag.StringVar(&settings.SelfCountryCode, "self-country", "", "The country code which phone number to send sms by twilio api.")
	flag.StringVar(&settings.OrderTime, "order-time", "", "The order time for sms message.")
	flag.StringVar(&settings.OrderTime, "o", "", "The order time for sms message. (shorten)")
	flag.Int64Var(&settings.LimitTime, "limit-time", 0, "The limit time for sms message.")
	flag.Int64Var(&settings.LimitTime, "l", 0, "The limit time for sms message. (shorten)")
	flag.Int64Var(&settings.Timeout, "timeout", 5, "The timeout for isp api requests. default is 5 seconds.")
	flag.Int64Var(&settings.Timeout, "t", 5, "The timeout for isp api requests. default is 5 seconds. (shorten)")
	flag.BoolVar(&settings.Check, "check", false, "Check the isp sms api is health or not. Default is false.")
	flag.BoolVar(&settings.Check, "k", false, "Check the isp sms api is health or not. Default is false. (shorten)")
	flag.Parse()
	return settings
}

func init() {
	params = parseArgs()

	// check the required flags
	if params.SmsIsp == "" {
		fmt.Println("The '-isp/-i' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.Username == "" {
		fmt.Println("The '-user/-u' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.Password == "" {
		fmt.Println("The '-password/-p' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.Message == "" {
		fmt.Println("The '-message/-m' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
	if params.PhoneNumber == "" {
		fmt.Println("The '-phone/-n' parameter is required, and it can't be empty.")
		os.Exit(1)
	}
}

func main() {
	sender := sms.SmsClient{}
	switch params.SmsIsp {
	case "hinet", "cht":
		client := &sms.HinetSmsClient {
			Username: params.Username,
			Password: params.Password,
			Timeout:  params.Timeout,
		}
		sender.Sender = client
		if params.Check {
			ok, err := sender.Sender.Check()
			if ok {
				fmt.Println("HiNet sms api is health.")
				return
			}
			fmt.Println(err)
		}

		switch params.SmsType {
		case "smart", "short", "long":
			msg := sms.HinetSmsMessage {
				SmsType:     params.SmsType,
				PhoneNumber: params.PhoneNumber,
				CountryCode: params.CountryCode,
				Message:     params.Message,
				OrderTime:   params.OrderTime,
				LimitTime:   params.LimitTime,
			}
			id, err := sender.Sender.Send(msg)
			if err != nil {
				fmt.Printf("Send Error: %s\n", err)
				return
			}
			fmt.Printf("SMS Message ID: %s\n", id)
		case "query", "cancel":
			qry := sms.HinetSmsQuery {
				SmsType:     params.SmsType,
				MessageType: params.MessageType,
				MessageId:   params.MessageId,
			}
			switch params.SmsType {
			case "query":
				resp, err := sender.Sender.SendQuery(qry)
				if err != nil {
					fmt.Printf("Query Error: %s\n", err)
					return
				}
				fmt.Printf("Query Status: %s\n", resp)
			case "cancel":
				if err := sender.Sender.SendCancelSms(qry); err != nil {
					fmt.Printf("Cancel Error: %s\n", err)
					return
				}
				fmt.Println("Sms cancelled successfully.")
			}
		default:
			fmt.Printf("Unsupport SMS Type: %s\n", params.SmsType)
		}
	case "twilio":
		if (params.SelfPhoneNumber == "" || params.SelfCountryCode == "") {
			fmt.Printf(
				"Error: %s\n",
				"Send sms via twilio api required the phone-number and country-code that send sms from.",
			)
			return
		}
		num, err := pn.Parse(params.SelfPhoneNumber, params.SelfCountryCode)
		if err != nil {
			fmt.Printf("Parse Phone Number Error: %s\n", err)
			return
		}
		client := &sms.TwilioClient {
			PhoneNumber: pn.Format(num, pn.E164),
			Timeout:     params.Timeout,
		}
		/*
		Send sms message via twilio api that could geiven authenetication for api by environment variables:
		  - TWILIO_ACCOUNT_SID
		  - TWILIO_AUTH_TOKEN
		  - TWILIO_API_KEY
		  - TWILIO_API_SECRET
		And the environment variables have high priority than related arguments.
		*/
		if ( os.Getenv("TWILIO_API_KEY") == "" || os.Getenv("TWILIO_API_SECRET") == "" ) {
			if ( os.Getenv("TWILIO_ACCOUNT_SID") == "" ) {
				client.AccountSid = params.Username
			} else {
				client.AccountSid = os.Getenv("TWILIO_ACCOUNT_SID")
			}
			client.AuthToken = params.Password
		} else {
			if ( os.Getenv("TWILIO_ACCOUNT_SID") == "" ) {
				client.AccountSid = params.Username
			} else {
				client.AccountSid = os.Getenv("TWILIO_ACCOUNT_SID")
			}
			client.ApiKey = os.Getenv("TWILIO_API_KEY")
			client.ApiSecret = os.Getenv("TWILIO_API_SECRET")
		}

		sender.Sender = client
		if params.Check {
			ok, err := sender.Sender.Check()
			if ok {
				fmt.Println("Twilio sms api is health.")
				return
			}
			fmt.Println(err)
		}

		switch params.SmsType {
		case "smart", "short", "long":
			msg := sms.TwilioSmsMessage {
				CountryCode:         params.CountryCode,
				PhoneNumber:         params.PhoneNumber,
				Message:             params.Message,
				MessagingServiceSid: params.MessageServiceSid,
				SendAt:              params.OrderTime,
			}
			id, err := sender.Sender.Send(msg)
			if err != nil {
				fmt.Printf("Send Error: %s\n", err)
				return
			}
			fmt.Printf("SMS Message ID: %s\n", id)
		case "query", "cancel":
			qry := sms.TwilioSmsQuery {
				MessageSid:   params.MessageId,
			}
			switch params.SmsType {
			case "query":
				resp, err := sender.Sender.SendQuery(qry)
				if err != nil {
					fmt.Printf("Query Error: %s\n", err)
					return
				}
				fmt.Printf("Query Status: %s\n", resp)
			case "cancel":
				if err := sender.Sender.SendCancelSms(qry); err != nil {
					fmt.Printf("Cancel Error: %s\n", err)
					return
				}
				fmt.Println("Sms cancelled successfully.")
			}
		default:
			fmt.Printf("Unsupport SMS Type: %s\n", params.SmsType)
		}
	}
}
