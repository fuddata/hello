package license

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/sys/windows/registry"
)

const licenseApiUrl = "http://192.168.8.40:8790"

const licPubKey = `
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Ga3dFd1lIS29aSXpqMENBUV
lJS29aSXpqMERBUWNEUWdBRUtORGdHRm02TmwvYzN4QzNnRlk4NFFTUlB4c2kN
CmxRc1BYU004bHZEVEJLWGw0OHMyQjFQQTRmUDM3MlFheTdMaDBiS1d3L05SQ2
txT1haZlZESWhpMHc9PQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo=`

type Request struct {
	App  string `json:"app"`
	Type int    `json:"type"`
	Guid string `json:"guid"`
}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

func GetLicenseStatus(app string) (error, int, bool) {
	// Read machine guid from registry
	m, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	defer m.Close()
	if err != nil {
		return errors.New("Cannot open Cryptography registry key"), -1, false
	}
	machineGuid, _, err := m.GetStringValue("MachineGuid")
	if err != nil {
		return errors.New("Cannot read MachineGuid registry value"), -1, false
	}

	// Read license key from registry
	firstLaunchDate := ""
	license := ""
	k, oldKey, err := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Fuddata\HelloWorld`, registry.READ+registry.WRITE)
	defer k.Close()
	if err != nil {
		return errors.New("Cannot open HelloWorld registry key"), -1, false
	}
	if oldKey {
		license, _, _ = k.GetStringValue("LicenseKey")
	}

	// Validate license key if defined
	validLicense := false
	if license != "" {
		validLicense, err = verifyLicKey(machineGuid, license)
		if err != nil {
			return errors.New(fmt.Sprintf("Verifying license: %s", err)), -1, false
		}
	}

	if validLicense {
		return nil, -1, false
	} else {
		// FixMe: Check if part of AD Domain or Azure AD
		licenseType := 1

		licStatus, licDetail, err := getRemote(app, machineGuid, licenseType)
		licenseOrdered := false
		switch licStatus {
		case 11:
			firstLaunchDate = licDetail
		case 12:
			licenseOrdered = true
			firstLaunchDate = licDetail
		case 13:
			validLicense, _ = verifyLicKey(machineGuid, licDetail)
			if validLicense {
				k.SetStringValue("LicenseKey", licDetail)
				return nil, -1, false
			}
		default:
			return errors.New(fmt.Sprintf("Unhandled licensing status. Details: %s", err)), -1, false
		}

		startDate, err := time.Parse("2006-01-02", firstLaunchDate)
		if err != nil {
			return errors.New(fmt.Sprintf("Parsing first launch date: %s", err)), -1, false
		}
		currentDate := time.Now()
		daysPassed := currentDate.Sub(startDate).Hours() / 24
		daysLeft := 3 - int(daysPassed)
		if daysLeft > 0 {
			return nil, daysLeft, licenseOrdered
		} else {
			return errors.New("Your trial period has ended."), -1, false
		}
	}
}

func verifyLicKey(data string, sign string) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(licPubKey)
	if err != nil {
		return false, errors.New(fmt.Sprintf("Decoding public key: %s", err))
	}

	block, _ := pem.Decode(pubKey)
	if block == nil {
		return false, errors.New("pubKey no pem data found")
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	pk := genericPublicKey.(*ecdsa.PublicKey)

	h := sha256.New()
	h.Write([]byte(data))
	hash := h.Sum(nil)

	bSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pk, hash, bSign), nil
}

func getRemote(app, guid string, licenseType int) (int, string, error) {
	data := Request{
		App:  app,
		Guid: guid,
		Type: licenseType,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return -1, "", errors.New(fmt.Sprintf("Marshaling licensing data: %s", err))
	}

	resp, err := http.Post(licenseApiUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return -1, "", errors.New(fmt.Sprintf("Sending license status request: %s", err))
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, "", errors.New(fmt.Sprintf("Reading license service response: %s", err))
	}

	var responseObj Response
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return -1, "", errors.New(fmt.Sprintf("Unmarshaling license service response: %s", err))
	}

	return responseObj.Status, responseObj.Message, nil
}
