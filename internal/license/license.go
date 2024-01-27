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
	"io"
	"net/http"
	"time"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"
)

type Win32_ComputerSystem struct {
	Manufacturer string
	Model        string
}

type Win32_BIOS struct {
	SerialNumber string
}

type Request struct {
	App  string `json:"app"`
	Type int    `json:"type"`
	Guid string `json:"guid"`
}

type Response struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

func GetLicenseStatus(apiUrl, app, pubKey string) (int, bool, error) {
	firstLaunchDate := ""
	license := ""
	validLicense := false
	clientID := ""
	licenseType := 1

	clientID = getEntraIdTenantId()
	if clientID != "" {
		fmt.Printf("Using EntraID based license\r\n\r\n")
		licenseType = 2
	} else {
		fmt.Printf("Using computer based license\r\n\r\n")

		// Generate single machine client ID in format:
		// Manufacturer|Model|SerialNumber
		var computerInfo []Win32_ComputerSystem
		query := "SELECT Manufacturer,Model FROM Win32_ComputerSystem"
		if err := wmi.Query(query, &computerInfo); err != nil {
			return -1, false, errors.New("cannot read BIOS information")
		}
		var biosInfo []Win32_BIOS
		query = "SELECT SerialNumber FROM Win32_BIOS"
		if err := wmi.Query(query, &biosInfo); err != nil {
			return -1, false, errors.New("cannot read BIOS information")
		}
		clientID = computerInfo[0].Manufacturer + "|" + computerInfo[0].Model + "|" + biosInfo[0].SerialNumber
	}

	// Read license key from registry
	k, oldKey, err := registry.CreateKey(registry.CURRENT_USER, `SOFTWARE\Fuddata\HelloWorld`, registry.READ+registry.WRITE)
	if err != nil {
		return -1, false, errors.New("cannot open HelloWorld registry key")
	}
	defer k.Close()
	if oldKey {
		license, _, _ = k.GetStringValue("LicenseKey")
	}

	// Validate license key if defined
	if license != "" {
		validLicense, err = verifyLicKey(clientID, pubKey, license)
		if err != nil {
			return -1, false, fmt.Errorf("verifying license: %s", err)
		}
	}

	if validLicense {
		return -1, false, nil
	}
	licStatus, licDetail, err := getRemote(apiUrl, app, clientID, licenseType)
	licenseOrdered := false
	switch licStatus {
	case 11, 21:
		firstLaunchDate = licDetail
	case 12, 22:
		licenseOrdered = true
		firstLaunchDate = licDetail
	case 13, 23:
		validLicense, _ = verifyLicKey(clientID, pubKey, licDetail)
		if validLicense {
			k.SetStringValue("LicenseKey", licDetail)
			return -1, false, nil
		}
	default:
		return -1, false, fmt.Errorf("unhandled licensing status. Details: %s", err)
	}

	startDate, err := time.Parse("2006-01-02", firstLaunchDate)
	if err != nil {
		return -1, false, fmt.Errorf("parsing first launch date: %s", err)
	}
	currentDate := time.Now()
	daysPassed := currentDate.Sub(startDate).Hours() / 24
	daysLeft := 3 - int(daysPassed)
	if daysLeft > 0 {
		return daysLeft, licenseOrdered, nil
	}
	return -1, false, errors.New("your trial period has ended")
}

func verifyLicKey(data, pKey, sign string) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(pKey)
	if err != nil {
		return false, fmt.Errorf("decoding public key: %s", err)
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

func getRemote(apiUrl, app, guid string, licenseType int) (int, string, error) {
	data := Request{
		App:  app,
		Guid: guid,
		Type: licenseType,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return -1, "", fmt.Errorf("marshaling licensing data: %s", err)
	}

	resp, err := http.Post(apiUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return -1, "", fmt.Errorf("sending license status request: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, "", fmt.Errorf("reading license service response: %s", err)
	}

	var responseObj Response
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return -1, "", fmt.Errorf("unmarshaling license service response: %s", err)
	}

	return responseObj.Status, responseObj.Message, nil
}

func getEntraIdTenantId() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}

	if len(subkeys) == 0 {
		return ""
	}

	joinInfoKey, err := registry.OpenKey(key, subkeys[0], registry.QUERY_VALUE)
	if err != nil {
		fmt.Printf("Error opening join info key: %v\n", err)
		return ""
	}
	defer joinInfoKey.Close()

	tenantId, _, err := joinInfoKey.GetStringValue("TenantId")
	if err != nil {
		fmt.Printf("Error reading TenantId value: %v\n", err)
		return ""
	}

	return tenantId
}
