package onvif

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/clbanning/mxj"
	uuid "github.com/satori/go.uuid"
)

// SOAP represents soap request and all of its components
type SOAP struct {
	Body     string
	XMLNs    []string
	User     string
	Password string
	TokenAge time.Duration
}

// MakeRequest creates new soap request instance
func MakeRequest(body string, xmlns []string, user string, password string, tokenAge time.Duration) SOAP {
	return SOAP{
		Body:     body,
		XMLNs:    xmlns,
		User:     user,
		Password: password,
		TokenAge: tokenAge,
	}
}

// Call calls the soap request on xaddr address and returns parsed xml response
func (soap SOAP) Call(xaddr string) (mxj.Map, error) {
	request := soap.createRequest()

	// veryfying
	urlXAddr, err := url.Parse(xaddr)
	if err != nil {
		return nil, err
	}

	if soap.User != "" {
		urlXAddr.User = url.UserPassword(soap.User, soap.Password)
	}

	requestBuffer := bytes.NewBuffer([]byte(request))
	req, err := http.NewRequest("Post", urlXAddr.String(), requestBuffer)
	if err != nil {
		return nil, err
	}

	// adding required soap headers
	req.Header.Set("Content-Type", "application/soap+xml")
	req.Header.Set("Charset", "utf-8")

	// calling soap request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// reading response body
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	xmlMAP, err := mxj.NewMapXml(resBody)
	if err != nil {
		return nil, err
	}

	if err, _ := xmlMAP.ValueForKey("Envolope.Body.Fault.Reason.Text.#text"); err != nil {
		return nil, errors.New(interfaceToString(err))
	}

	return xmlMAP, nil
}

func (soap SOAP) createRequest() string {
	request := `<?xml version="1.0" encoding="UTF-8"?>`
	request += `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"`

	// Set XML namespace
	for _, namespace := range soap.XMLNs {
		request += " " + namespace
	}
	request += ">"

	// Set request header
	if soap.User != "" {
		request += "<s:Header>" + soap.createUserToken() + "</s:Header>"
	}

	// Set request body
	request += "<s:Body>" + soap.Body + "</s:Body>"

	// Close request envelope
	request += "</s:Envelope>"

	// Clean request
	request = regexp.MustCompile(`\>\s+\<`).ReplaceAllString(request, "><")
	request = regexp.MustCompile(`\s+`).ReplaceAllString(request, " ")

	return request
}

func (soap SOAP) createUserToken() string {
	nonce := uuid.NewV4().Bytes()
	nonce64 := base64.StdEncoding.EncodeToString(nonce)
	timestamp := time.Now().Add(soap.TokenAge).UTC().Format(time.RFC3339)
	token := string(nonce) + timestamp + soap.Password

	sha := sha1.New()
	sha.Write([]byte(token))
	shaToken := sha.Sum(nil)
	shaDigest64 := base64.StdEncoding.EncodeToString(shaToken)

	return `<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  		<UsernameToken>
    		<Username>` + soap.User + `</Username>
    		<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">` + shaDigest64 + `</Password>
    		<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` + nonce64 + `</Nonce>
    		<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` + timestamp + `</Created>
		</UsernameToken>
	</Security>`
}
