/**
   esp32 firmware OTA

   Purpose: Perform an OTA update from a bin located on a webserver (HTTPS)

   Setup:
   Step 1 : Set your WiFi (ssid & password)
   Step 2 : set esp32fota()
   Step 3 : Provide SPIFFS filesystem with root_ca.pem of your webserver

   Upload:
   Step 1 : Menu > Sketch > Export Compiled Library. The bin file will be saved in the sketch folder (Menu > Sketch > Show Sketch folder)
   Step 2 : Upload it to your webserver
   Step 3 : Update your firmware JSON file ( see firwmareupdate )

*/

// declare filesystem first !

//#include <SD.h>
//#include <SD_MMC.h>
//#include <SPIFFS.h>
#include <LittleFS.h>
//#include <PSRamFS.h>

#include <esp32fota.h> // fota pulls WiFi library

CryptoFileAsset *MyRootCA = new CryptoFileAsset( "/root_ca.pem", &LittleFS );
// CryptoFileAsset *MyRootCA = new CryptoFileAsset( "/root_ca.pem", &SPIFFS );
// CryptoMemAsset *MyRootCA = new CryptoMemAsset("Certificates Chain", root_ca,     strlen(root_ca)+1 );

// CryptoFileAsset *MyRSAKey = new CryptoFileAsset( "/rsa_key.pub", &SPIFFS );
// CryptoFileAsset *MyRSAKey = new CryptoFileAsset( "/rsa_key.pub", &LittleFS );
// CryptoMemAsset *MyRSAKey = new CryptoMemAsset("RSA Public Key",     rsa_key_pub, strlen(rsa_key_pub)+1 );

// Change to your WiFi credentials
const char *ssid = "";
const char *password = "";

// esp32fota esp32fota("<Type of Firme for this device>", <this version>, <validate signature>, <allow insecure TLS>);
esp32FOTA esp32FOTA("esp32-fota-http", 1, false );

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

}


void setup()
{
  Serial.begin(115200);
  // Provide filesystem with root_ca.pem to validate server certificate
  if( ! LittleFS.begin( false ) ) {
    Serial.println("LittleFS Mounting failed, aborting!");
    while(1) vTaskDelay(1);
  }
  // use this when more than one filesystem is used in the sketch
  // esp32FOTA.setCertFileSystem( &SD );

  esp32FOTA.checkURL = "http://server/fota/fota.json";
  esp32FOTA.setRootCA( MyRootCA );
  //esp32FOTA.setPubKey( MyRSAKey );

  // show progress when an update occurs (e.g. on a TFT display)
  esp32FOTA.setProgressCb( [](size_t progress, size_t size) {
      if( progress == size || progress == 0 ) Serial.println();
      Serial.print(".");
  });

  // add some custom headers to the http queries
  esp32FOTA.setExtraHTTPHeader("Authorization", "Basic <credentials>");

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

