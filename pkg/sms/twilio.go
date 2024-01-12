package sms

import (
	"fmt"
	"net/http"
	"time"

	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
	pn "github.com/nyaruka/phonenumbers"
)

type TwilioClient struct {
	AccountSid   string
	AuthToken   string
	ApiKey      string
	ApiSecret   string
	PhoneNumber string // E164 format
	Timeout     int64
}

type TwilioSmsMessage struct {
	CountryCode          string
	PhoneNumber          string
	Message              string
	MessagingServiceSid  string // Without a MessagingServiceSid, Twilio treats the message as a non-scheduled message.
	SendAt               string // time with ISO-8601, eg. 2021-11-30T20:36:27Z
}

type TwilioSmsQuery struct {
	MessageSid    string
}

func NewTwilioClient(sid, token, number, countryCode string) (*TwilioClient, error) {
	if countryCode == "" {
		countryCode = "TW"
	}
	num, err := pn.Parse(number, countryCode)
	if err != nil {
		return nil, err
	}
	client := &TwilioClient {
		AccountSid:   sid,
		AuthToken:   token,
		PhoneNumber: pn.Format(num, pn.E164),
	}
	return client, nil
}

func (tc *TwilioClient) Check() (bool, error) {
	var timeout int64 = 5
	if tc.Timeout != 0 {
		timeout = tc.Timeout
	}
	client := &http.Client {
		Timeout: time.Duration(timeout) * time.Second,
	}

	// https://api.twilio.com/2010-04-01
	req, err := http.NewRequest("GET", "https://messaging.twilio.com/v1", nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, nil
}

func (tc *TwilioClient) Send(data interface{}) (string, error) {
	msgBody := data.(TwilioSmsMessage)

	var client *twilio.RestClient
	if tc.ApiKey == "" || tc.ApiSecret == "" {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username: tc.AccountSid,
				Password: tc.AuthToken,
			},
		)
	} else {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username:   tc.ApiKey,
				Password:   tc.ApiSecret,
				AccountSid: tc.AccountSid,
			},
		)
	}

	countryCode := "TW"
	if msgBody.CountryCode != "" {
		countryCode = msgBody.CountryCode
	}
	num, err := pn.Parse(msgBody.PhoneNumber, countryCode)
	if err != nil {
		return "", err
	}

	params := &twilioApi.CreateMessageParams{}
	params.SetFrom(tc.PhoneNumber)
	params.SetTo(pn.Format(num, pn.E164))
	params.SetTo(msgBody.Message)

	if msgBody.SendAt != "" && msgBody.MessagingServiceSid != "" {
		params.SetScheduleType("fixed")
		params.SetMessagingServiceSid(msgBody.MessagingServiceSid)

		// RFC3339 is equivalent to ISO 8601
		// params.SetSendAt(time.Date(2021, 11, 30, 20, 36, 27, 0, time.UTC))
		sendAt, err := time.Parse(time.RFC3339, msgBody.SendAt)
		if err != nil {
			return "", err
		}
		params.SetSendAt(sendAt)
	}

	resp, err := client.Api.CreateMessage(params)
	if err != nil {
		return "", err
	} else {
		if ( resp.Sid != nil && resp.ErrorCode == nil ) {
			return *resp.Sid, nil
		} else {
			return "", fmt.Errorf("Send Sms Error (%d): %s", *resp.ErrorCode, *resp.ErrorMessage)
		}
	}
}

func (tc *TwilioClient) SendQuery(data interface{}) (string, error) {
	queryMsg := data.(TwilioSmsQuery)

	var client *twilio.RestClient
	if tc.ApiKey == "" || tc.ApiSecret == "" {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username: tc.AccountSid,
				Password: tc.AuthToken,
			},
		)
	} else {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username:   tc.ApiKey,
				Password:   tc.ApiSecret,
				AccountSid: tc.AccountSid,
			},
		)
	}

	params := &twilioApi.FetchMessageParams{}
	params.SetPathAccountSid(tc.AccountSid)

	resp, err := client.Api.FetchMessage(queryMsg.MessageSid, params)
	if err != nil {
		return "", err
	}
	return *resp.Status, nil
}

func (tc *TwilioClient) SendCancelSms(data interface{}) error {
	queryMsg := data.(TwilioSmsQuery)

	var client *twilio.RestClient
	if tc.ApiKey == "" || tc.ApiSecret == "" {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username: tc.AccountSid,
				Password: tc.AuthToken,
			},
		)
	} else {
		client = twilio.NewRestClientWithParams(
			twilio.ClientParams {
				Username:   tc.ApiKey,
				Password:   tc.ApiSecret,
				AccountSid: tc.AccountSid,
			},
		)
	}

	params := &twilioApi.UpdateMessageParams{}
	params.SetStatus("canceled")

	_, err := client.Api.UpdateMessage(queryMsg.MessageSid, params)
	if err != nil {
		return err
	}

	return nil
}
