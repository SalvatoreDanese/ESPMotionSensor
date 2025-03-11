#include <Wire.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <Crypto.h>
#include <RNG.h>
#include <AES.h>
#include <CTR.h>
#include <Curve25519.h>
#include <string.h>
#include <SPI.h> 
#include <MFRC522.h>
#include <Wire.h> 

#define SS_PIN 5 
#define RST_PIN 22


MFRC522 mfrc522(SS_PIN, RST_PIN);


char *ssid = "Infostrada-896701";            // your network SSID (name)
char password[10];       // your network password
int status = WL_IDLE_STATUS;     // the Wifi radio's status
WiFiClient client;
IPAddress ip(172,20,10,2);            // local port to listen on      
CTR<AES128> cipher;
int code[] = {69,6,145,172}; //UID per sblocco
bool state=0;
int codeRead = 0;
const int buzzer = 14;


String uidString;



static uint8_t alice_private[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x76, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x52, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2d, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2d, 0x2b
    };

static uint8_t const bob_public[32] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    };

static uint8_t iv[16] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static uint8_t encPass[10] = {0x88, 0x57, 0x92, 0xce, 0xfd, 0x62, 0x10, 0x96, 0x7b, 0xb9};
uint8_t *shared_secret;
uint8_t result[32];

byte rec[2];
byte rec1[2];
byte output[2];
byte pass[10];

byte received[1];

 

void setup() {
  SPI.begin();       
  mfrc522.PCD_Init(); 
  Serial.println("Arduino RFID reading UID");
  

  pinMode(buzzer, OUTPUT);

  alice_private[0] &= 0xF8;
  alice_private[31] = (alice_private[31] & 0x7F) | 0x40;


  Curve25519::eval(result, alice_private, bob_public);
  shared_secret = result;

  decryptMine(&cipher, encPass, 10, pass);

  for(int i = 0; i < 10; i++){
    sprintf(password+i, "%c", pass[i]);
  }




  Serial.begin(9600);


  // attempt to connect to WiFi network
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
  if (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("WiFi Connect Failed! Rebooting...");
    delay(1000);
    ESP.restart();
  }

  
  Serial.println("Connected to wifi");

  Serial.println("\nStarting connection to server...");
  // if you get a connection, report back via serial:
  if (client.connect(ip, 1234)) {
    Serial.println("Connected to server");
    client.println("2");
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
  if(client.available()){
    byte output1[1];
    client.read(received, 1);
    Serial.print("Received: ");
    Serial.print(received[0]);
    decryptMine(&cipher, received, 1, output1);
    Serial.println("-");
    Serial.print("Dec: ");
    Serial.print(output1[0]);
    if(output1[0] == 104){
      Serial.println("Movimento rilevato");
      digitalWrite(buzzer, HIGH);
      state=1;
    } 
  }
    if(state==1){
      if( mfrc522.PICC_IsNewCardPresent()){
        Serial.println("Present");
        if( mfrc522.PICC_ReadCardSerial()){

          Serial.println("Tag UID:");
          
          
          //Stampa dei TAG UID su serial 
          for(byte i = 0; i < mfrc522.uid.size; i++){
            Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
            Serial.print(mfrc522.uid.uidByte[i], HEX);
            
          }

          Serial.println();
          int i = 0;
          boolean match = true;
          //Confronto byte array UID
          while(i<mfrc522.uid.size){
            if(!(int(mfrc522.uid.uidByte[i]) == int(code[i]))){
              match=false;
            }
            i++;
          }

          
          //IF match (i due byte array)
          if(!match){
            
            Serial.println("Access denied");
            
          }
          if(match){
            Serial.println("Alarm deactivated");
            digitalWrite(buzzer, LOW);
            state=0;
          }

            }  // fine secondo IF
      } //fine primo IF
    
  
  }
  
} //loop

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


