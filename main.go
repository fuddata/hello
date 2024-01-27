package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/hello/internal/license"
)

const licenseApiUrl = "http://192.168.8.40:8888/api/license"

const licPubKey = `
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Ga3dFd1lIS29aSXpqMENBUV
lJS29aSXpqMERBUWNEUWdBRUtORGdHRm02TmwvYzN4QzNnRlk4NFFTUlB4c2kN
CmxRc1BYU004bHZEVEJLWGw0OHMyQjFQQTRmUDM3MlFheTdMaDBiS1d3L05SQ2
txT1haZlZESWhpMHc9PQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo=`

const helloWorld = ` _   _      _ _        __        __         _     _
| | | | ___| | | ___   \ \      / /__  _ __| | __| |
| |_| |/ _ \ | |/ _ \   \ \ /\ / / _ \| '__| |/ _  |
|  _  |  __/ | | (_) |   \ V  V / (_) | |  | | (_| |
|_| |_|\___|_|_|\___/     \_/\_/ \___/|_|  |_|\__,_|

`

func main() {
	trialLeft, ordered, err := license.GetLicenseStatus(licenseApiUrl, "HELLOWORLD", licPubKey)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}
	if trialLeft != -1 {
		if ordered {
			color.Cyan("License ordered, waiting for payment. You have %d days left in your trial period.", trialLeft)
		} else {
			color.Yellow("Warning: Unlicensed copy of application. You have %d days left in your trial period.", trialLeft)
		}
	} else {
		color.Green("Info: Licensed copy of application\r\n")
	}

	color.HiBlue(helloWorld)
	fmt.Printf("Press any key to close this window")
	fmt.Scanln()
}
