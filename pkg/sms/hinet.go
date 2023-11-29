package sms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	pn "github.com/nyaruka/phonenumbers"
)

type HinetSmsClient struct {
	Username     string
	Password     string
	Timeout      int64
}

type HinetSmsMessage struct {
	SmsType      string  // smart, long or short
	PhoneNumber  string
	CountryCode  string
	Message      string
	OrderTime    string
	LimitTime    int64
}

type HinetSmsQuery struct {
	SmsType      string  // query or cancel
	MessageType  string  // long or short
	MessageId    string
}

type hinetSmsRequestBody struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	Mobile       string   `json:"mobile"`
	Message      string   `json:"message"`
	OrderTime    string   `json:"order_time,omitempty"`
	LimitTime    int64    `json:"limit_time,omitempty"`
}

type hinetSmsQueryBody struct {
	Username     string   `json:"username"`
	Password     string   `json:"password"`
	MessageId    string   `json:"message_id"`
	MsgType      int      `json:"msg_type"` // msg_type is 2 for short sms. 12 for long sms.
}

type hinetSmsResponse struct {
	RetCode      int      `json:"ret_code"`
	RetContent   string   `json:"ret_content"`
	MsgType      string   `json:"msg_type,omitempty"`
}

func NewHinetSmsHttpClient(smsType string, body []byte, timeout int64) (*http.Client, *http.Request, error) {
	var uri string
	switch smsType {
	case "short":
		uri = "/api/sendShortSMS/v1"
	case "long":
		uri = "/api/sendLongSMS/v1"
	case "query":
		uri = "/api/querySMS/v1"
	case "cancel":
		uri = "/api/cancelSMS/v1"
	default:
		uri = "/api/sendSMS/v1"
	}
	if timeout == 0 {
		timeout = 5
	}
	client := &http.Client {
		Timeout: time.Duration(timeout) * time.Second,
	}
	url := fmt.Sprintf("%s%s", "https://api.sms.hinet.net", uri)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "text/plain; charset=UTF-8")
	return client, req, nil
}

func (hsc *HinetSmsClient) Check() (bool, error) {
	var timeout int64
	if hsc.Timeout != 0 {
		timeout = hsc.Timeout
	}
	client := &http.Client {
		Timeout: time.Duration(timeout) * time.Second,
	}
	req, err := http.NewRequest("GET", "https://api.sms.hinet.net", nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		if string(body) == "ok" {
			return true, nil
		}
	}

	return false, fmt.Errorf("Hinet sms api is unhealth!")
}

func (hsc *HinetSmsClient) Send(data interface{}) (string, error) {
	var (
		smsType  string
		smsResp hinetSmsResponse
	)
	msgBody := data.(HinetSmsMessage)
	pwdDecoded, err := base64.StdEncoding.DecodeString(hsc.Password)
	if err != nil {
		return "", err
	}

	countryCode := "TW"
	if msgBody.CountryCode != "" {
		countryCode = msgBody.CountryCode
	}
	num, err := pn.Parse(msgBody.PhoneNumber, countryCode)
	if err != nil {
		return "", err
	}

	reqBody := &hinetSmsRequestBody {
		Username: hsc.Username,
		Password: strings.Replace(string(pwdDecoded), "\n", "", -1),
		Mobile:   pn.Format(num, pn.E164),
		Message:  msgBody.Message,
	}
	if msgBody.LimitTime != 0 {
		reqBody.LimitTime = msgBody.LimitTime
	}
	if msgBody.OrderTime != "" {
		reqBody.OrderTime = msgBody.OrderTime
	}
	jsonData, _ := json.Marshal(reqBody)

	// smart sms: according length of content to choose short or long sms automatically
	if  msgBody.SmsType == "" {
		smsType = "smart"
	} else if msgBody.SmsType != "" && msgBody.SmsType != "smart" &&
		msgBody.SmsType != "long" && msgBody.SmsType != "short" {
			return "", fmt.Errorf("Unsuport SMS Type: %s\n", msgBody.SmsType)
	} else {
		smsType = msgBody.SmsType
	}
	client, req, err := NewHinetSmsHttpClient(smsType, jsonData, hsc.Timeout)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		if err = json.Unmarshal(body, &smsResp); err != nil {
			return "", err
		}
		if smsResp.RetCode == 0 {
			return smsResp.RetContent, nil
		}
		return "", fmt.Errorf(smsResp.RetContent)
	}
	return "", fmt.Errorf("SMS api request failed!")
}

func (hsc *HinetSmsClient) SendQuery(data interface{}) (string, error) {
	var smsResp hinetSmsResponse
	qryBody := data.(HinetSmsQuery)
	pwdDecoded, err := base64.StdEncoding.DecodeString(hsc.Password)
	if err != nil {
		return "", err
	}
	reqBody := &hinetSmsQueryBody {
		Username:   hsc.Username,
		Password:   strings.Replace(string(pwdDecoded), "\n", "", -1),
		MessageId:  qryBody.MessageId,
	}
	switch qryBody.MessageType {
	case "long":
		reqBody.MsgType = 12
	default:
		reqBody.MsgType = 2
	}
	jsonData, _ := json.Marshal(reqBody)
	client, req, err := NewHinetSmsHttpClient("query", jsonData, hsc.Timeout)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		if err = json.Unmarshal(body, &smsResp); err != nil {
			return "", err
		}
		return smsResp.RetContent, nil
	}
	return "", fmt.Errorf("SMS api request failed!")
}

func (hsc *HinetSmsClient) SendCancelSms(data interface{}) error {
	var smsResp hinetSmsResponse
	qryBody := data.(HinetSmsQuery)
	pwdDecoded, err := base64.StdEncoding.DecodeString(hsc.Password)
	if err != nil {
		return err
	}
	reqBody := &hinetSmsQueryBody {
		Username:   hsc.Username,
		Password:   strings.Replace(string(pwdDecoded), "\n", "", -1),
		MessageId:  qryBody.MessageId,
	}
	switch qryBody.MessageType {
	case "long":
		reqBody.MsgType = 12
	default:
		reqBody.MsgType = 2
	}
	jsonData, _ := json.Marshal(reqBody)
	client, req, err := NewHinetSmsHttpClient("cancel", jsonData, hsc.Timeout)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(body, &smsResp); err != nil {
			return err
		}
		if smsResp.RetCode == 0 {
			return nil
		}
		return fmt.Errorf(smsResp.RetContent)
	}
	return fmt.Errorf("SMS api request failed!")
}
