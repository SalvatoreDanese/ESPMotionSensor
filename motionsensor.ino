#include "WiFiEsp.h"
#include <WiFiEspClient.h>
#include "SoftwareSerial.h"
#include <Crypto.h>
#include <RNG.h>
#include <AES.h>
#include <CTR.h>
#include <Curve25519.h>
#include <string.h>


int inputPin = 3;               // choose the input pin D3(for PIR sensor)
int pirState = LOW;             // we start, assuming no motion detected
int val = 0;                    // variable for reading the pin status
SoftwareSerial softserial(4, 5); // A9 to ESP_TX, A8 to ESP_RX by default

char ssid[] = "Infostrada-896701";            // your network SSID (name)
char password[10];        // your network password

int status = WL_IDLE_STATUS;     // the Wifi radio's status
WiFiEspClient client;
IPAddress ip(172,20,10,4);            // local port to listen on      

CTR<AES128> cipher;
char buffer[50];

byte rec[2];
byte rec1[2];
byte pass[10];
byte output[2];

static uint8_t alice_private[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };

static uint8_t const bob_public[32] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    };

static uint8_t iv[16] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static uint8_t encPass[10] = {0xe4, 0x61, 0xfd, 0x01, 0x68, 0x5a, 0xb7, 0xdd, 0xff, 0xdc};


static uint8_t const plaintext1[] = {0x41, 0x41};
static uint8_t const plaintext2[] = {0x42, 0x42};


uint8_t *shared_secret;
uint8_t result[32];

 

void setup() {
  

  alice_private[0] &= 0xF8;
  alice_private[31] = (alice_private[31] & 0x7F) | 0x40;

  Curve25519::eval(result, alice_private, bob_public);
  shared_secret = result;

  decryptMine(&cipher, encPass, 10, pass);

  for(int i = 0; i < 10; i++){
    sprintf(password+i, "%c", pass[i]);
  }

  
  pinMode(pirState, INPUT);

  Serial.begin(9600);   // initialize serial for debugging
  softserial.begin(115200);
  softserial.write("AT+CIOBAUD=9600\r\n");
  softserial.write("AT+RST\r\n");
  softserial.begin(9600);    // initialize serial for ESP module
  WiFi.init(&softserial);    // initialize ESP module

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  // attempt to connect to WiFi network
  while ( status != WL_CONNECTED) {
    Serial.print("Attempting to connect to WPA SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network
    status = WiFi.begin(ssid, password);
  }
  
  Serial.println("Connected to wifi");
  printWifiStatus();

  Serial.println("\nStarting connection to server...");
  // if you get a connection, report back via serial:
  if (client.connect(ip, 1234)) {
    Serial.println("Connected to server");
    client.println("1");
  }
  
  

  while(rec[0]==0 && rec[1]==0){
  if(client.available()) {
    client.read(rec, 2);
    Serial.println(rec[0]);
    Serial.println(rec[1]);
    decryptMine(&cipher, rec, 2, rec1);
    }
  }


  Serial.println(rec1[0]);
  Serial.println(rec1[1]);
  for(int i = 0; i < 16; i++){
    iv[i] ^= rec1[0];
  }
 
}
 
void loop() {
  
  val = digitalRead(inputPin);  // read input value
  if (val == HIGH) {            // check if the input is HIGH
 
    if (pirState == LOW) {
      // we have just turned on
      Serial.println("Motion detected!");
      encryptMine(&cipher,plaintext1);
      sprintf(buffer, "%dx%d\0", output[0], output[1]);
      client.println(buffer);     
      Serial.println(buffer);
      delay(100);
      // We only want to print on the output change, not state
      pirState = HIGH;
    }
  } else {
 
    if (pirState == HIGH){
      // we have just turned off
      Serial.println("Motion ended!");
      encryptMine(&cipher,plaintext2);
      sprintf(buffer, "%dx%d\0", output[0], output[1]);
      client.println(buffer);     
      Serial.println(buffer); 
      delay(100);
      // We only want to print on the output change, not state
      pirState = LOW;
    }
  }
}

void printWifiStatus()
{
  // print the SSID of the network you're attached to
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your WiFi shield's IP address
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);
}

void encryptMine(Cipher* cipher, byte *plaintext)
{
    
    size_t posn, len, inc = 1;

    cipher->clear();
    if (!cipher->setKey(shared_secret, 16)) {
        Serial.print("setKey ");
    }
    if (!cipher->setIV(iv, 16)) {
        Serial.print("setIV ");
    }

    memset(output, 0xBA, sizeof(output));

    for (posn = 0; posn < 2; posn += inc) {
        len = 2 - posn;
        if (len > inc)
            len = inc;
        cipher->encrypt(output + posn, plaintext + posn, len);
    }

  
  
}

void decryptMine(Cipher* cipher, byte *ciphertext, int length, byte *plaintext){

  size_t posn, len, inc = 1;
  cipher->clear();
    if (!cipher->setKey(shared_secret, 16)) {
        Serial.print("setKey ");
    }
    if (!cipher->setIV(iv, 16)) {
        Serial.print("setIV ");
    }

    for (posn = 0; posn < length; posn += inc) {
        len = length - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(plaintext + posn, ciphertext + posn, len);
    }

}


