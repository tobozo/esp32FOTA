/**
   esp32 firmware OTA

   Purpose: Perform an OTA update to both firmware and filesystem from binaries located
            on a webserver (HTTPS) while using progmem to check for certificate validity


*/

#include <esp32fota.h>

#include "root_ca.h"
#include "pub_key.h"

// esp32fota settings
const int firmware_version  = 3;
#if !defined FOTA_URL
  #define FOTA_URL "http://server/fota/fota.json"
#endif
const char* firmware_name   = "esp32-fota-http";
const bool check_signature  = false;
const bool disable_security = false;
// for debug only
const char* description     = "PROGMEM example with security";

const char* fota_debug_fmt = R"DBG_FMT(

***************** STAGE %i *****************

  Description      : %s
  Firmware type    : %s
  Firmware version : %i
  Signature check  : %s
  TLS Cert check   : %s

********************************************

)DBG_FMT";

// esp32fota esp32fota("<Type of Firme for this device>", <this version>, <validate signature>, <allow insecure TLS>);
esp32FOTA esp32FOTA( String(firmware_name), firmware_version, check_signature, disable_security );

// create an abstraction of the root_ca file
CryptoMemAsset *MyRootCA = new CryptoMemAsset("Root CA", root_ca, strlen(root_ca)+1 );

void setup_wifi()
{
  delay(10);
  Serial.print("Connecting to WiFi ");
  Serial.println( WiFi.macAddress() );

  WiFi.begin(); // no WiFi creds in this demo :-)

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println(WiFi.localIP());

  esp32FOTA.setRootCA( MyRootCA );

}


void setup()
{
  Serial.begin(115200);
  Serial.printf( fota_debug_fmt, firmware_version, description, firmware_name, firmware_version, check_signature?"Enabled":"Disabled", disable_security?"Disabled":"Enabled" );

  esp32FOTA.checkURL = FOTA_URL;

  setup_wifi();
}

void loop()
{

  bool updatedNeeded = esp32FOTA.execHTTPcheck();
  if (updatedNeeded)
  {
    esp32FOTA.execOTA();
  }

  delay(20000);
}

