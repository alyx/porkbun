package porkbun

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type apiRequest interface{}

type authRequest struct {
	APIKey       string `json:"apikey"`
	SecretAPIKey string `json:"secretapikey"`
	apiRequest
}

func (f authRequest) MarshalJSON() ([]byte, error) {
	type clone authRequest
	c := clone(f)

	root, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	if c.apiRequest == nil {
		return root, nil
	}

	embedded, err := json.Marshal(c.apiRequest)
	if err != nil {
		return nil, err
	}

	return []byte(string(root[:len(root)-1]) + ",   " + string(embedded[1:])), nil
}

// Status the API response status.
type Status struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func (a Status) Error() string {
	return fmt.Sprintf("%s: %s", a.Status, a.Message)
}

// ServerError the API server error.
type ServerError struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message,omitempty"`
}

func (a ServerError) Error() string {
	return fmt.Sprintf("status: %d message: %s", a.StatusCode, a.Message)
}

// Record a DNS record.
type Record struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Content string `json:"content,omitempty"`
	TTL     string `json:"ttl,omitempty"`
	Prio    string `json:"prio,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

type pingResponse struct {
	Status
	YourIP string `json:"yourIp"`
}

type createResponse struct {
	Status
	ID int `json:"id"`
}

type retrieveResponse struct {
	Status
	Records []Record `json:"records"`
}

// SSLBundle a  SSL certificate bundle.
type SSLBundle struct {
	IntermediateCertificate string `json:"intermediatecertificate"`
	CertificateChain        string `json:"certificatechain"`
	PrivateKey              string `json:"privatekey"`
	PublicKey               string `json:"publickey"`
}

type sslBundleResponse struct {
	Status
	SSLBundle
}

// Domain a Domain.
// XXX: Figure out how to fix the json.Number nonsense
type Domain struct {
	Domain       string        `json:"domain,omitempty"`
	Status       string        `json:"status,omitempty"`
	TLD          string        `json:"tld,omitempty"`
	CreateDate   time.Time     `json:"createDate,omitempty"`
	ExpireDate   time.Time     `json:"expireDate,omitempty"`
	SecurityLock bool          `json:"securityLock"`
	WHOISPrivacy bool          `json:"whoisPrivacy"`
	AutoRenew    bool          `json:"autoRenew"`
	NotLocal     bool          `json:"notLocal"`
	Labels       []DomainLabel `json:"labels"`
}

func (d *Domain) UnmarshalJSON(b []byte) error {
	var createDateStr string
	var expireDateStr string
	var securityLockInt, whoisPrivacyInt, autoRenewInt, notLocalInt int
	var securityLockStr, whoisPrivacyStr, autoRenewStr, notLocalStr string

	var objMap map[string]*json.RawMessage
	err := json.Unmarshal(b, &objMap)
	if err != nil {
		return err
	}

	// Unmarshal all the regular strings.
	err = json.Unmarshal(*objMap["domain"], &d.Domain)
	if err != nil {
		return err
	}
	fmt.Println(d.Domain)

	err = json.Unmarshal(*objMap["status"], &d.Status)
	if err != nil {
		return err
	}

	err = json.Unmarshal(*objMap["tld"], &d.TLD)
	if err != nil {
		return err
	}

	// CreateDate and ExpireDate are both times, convert the strings.
	if objMap["createDate"] != nil {
		err = json.Unmarshal(*objMap["createDate"], &createDateStr)
		if err != nil {
			return err
		}

		d.CreateDate, err = time.Parse("2006-01-02 15:04:05", createDateStr)
		if err != nil {
			return err
		}
	} else {
		d.CreateDate = time.Unix(0, 0)
	}

	err = json.Unmarshal(*objMap["expireDate"], &expireDateStr)
	if err != nil {
		return err
	}
	d.ExpireDate, err = time.Parse("2006-01-02 15:04:05", expireDateStr)
	if err != nil {
		return err
	}

	// Here there be complications. Porkbun seems to treat all these values
	// like they could be booleans. They're all items that are either on (true)
	// or off (false). However responses end up being either int(0) for "False"
	// or string(1) for "True"
	//
	// Technically we could use a json.Number here and move the complexity
	// to end-user problems, but it's cleaner for the end user to just handle it here.
	// Since we're having to manually fiddle with it anyway, we can convert these wanna-be
	// integers into regular booleans too.
	err = json.Unmarshal(*objMap["securityLock"], &securityLockInt)
	if err != nil {
		err = json.Unmarshal(*objMap["securityLock"], &securityLockStr)
		if err != nil {
			return err
		}
		toInt, err := strconv.Atoi(securityLockStr)
		if err != nil {
			return err
		}
		securityLockInt = toInt
	}
	switch securityLockInt {
	case 0:
		d.SecurityLock = false
	case 1:
		d.SecurityLock = true
	default:
		return errors.New("SecurityLock response not a boolean")
	}

	err = json.Unmarshal(*objMap["whoisPrivacy"], &whoisPrivacyInt)
	if err != nil {
		err = json.Unmarshal(*objMap["whoisPrivacy"], &whoisPrivacyStr)
		if err != nil {
			return err
		}
		toInt, err := strconv.Atoi(whoisPrivacyStr)
		if err != nil {
			return err
		}
		whoisPrivacyInt = toInt
	}
	switch whoisPrivacyInt {
	case 0:
		d.WHOISPrivacy = false
	case 1:
		d.WHOISPrivacy = true
	default:
		return errors.New("WhoisPrivacy response not a boolean")
	}

	err = json.Unmarshal(*objMap["autoRenew"], &autoRenewInt)
	if err != nil {
		err = json.Unmarshal(*objMap["autoRenew"], &autoRenewStr)
		if err != nil {
			return err
		}
		toInt, err := strconv.Atoi(autoRenewStr)
		if err != nil {
			return err
		}
		autoRenewInt = toInt
	}
	switch autoRenewInt {
	case 0:
		d.AutoRenew = false
	case 1:
		d.AutoRenew = true
	default:
		return errors.New("AutoRenew response not a boolean")
	}

	err = json.Unmarshal(*objMap["notLocal"], &notLocalInt)
	if err != nil {
		err = json.Unmarshal(*objMap["notLocal"], &notLocalStr)
		if err != nil {
			return err
		}
		toInt, err := strconv.Atoi(notLocalStr)
		if err != nil {
			return err
		}
		notLocalInt = toInt
	}
	switch notLocalInt {
	case 0:
		d.NotLocal = false
	case 1:
		d.NotLocal = true
	default:
		return errors.New("NotLocal response not a boolean")
	}

	if objMap["labels"] != nil {
		err = json.Unmarshal(*objMap["labels"], &d.Labels)
		if err != nil {
			return err
		}
	} else {
		d.Labels = nil
	}

	return nil
}

type DomainLabel struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title,omitempty"`
	Color string `json:"color,omitempty"`
}

type listDomainsResponse struct {
	Status
	Domains []Domain `json:"domains"`
}

type getNameServersResponse struct {
	Status
	NameServers []string `json:"ns"`
}
