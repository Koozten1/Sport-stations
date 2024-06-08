#include <iarduino_RTC.h>  
#include <SPI.h>
#include <MFRC522.h>
#include <GyverPower.h>

#define RST_PIN         9          // Configurable, see typical pin layout above
#define SS_PIN          10         // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance

int time_slipe = 5000;
int time_out = millis();

void go_sleep(){
  digitalWrite(8, LOW);
  
  pinMode(11, INPUT);
  pinMode(10, INPUT);
  digitalWrite(11, LOW);
  digitalWrite(10, LOW);
  digitalWrite(RST_PIN, LOW); 
  power.sleepDelay(time_slipe);
}


void wake_up(){
  digitalWrite(8, HIGH);
  pinMode(11, OUTPUT);
  pinMode(10, OUTPUT);
  digitalWrite(RST_PIN, HIGH);          
  delayMicroseconds(1);                 
  digitalWrite(RST_PIN, LOW);           
  mfrc522.PCD_Init();  
//  delay(5000);
}



void setup() {
   pinMode(8,OUTPUT);
    digitalWrite(8, HIGH);
    delay(1000);
  Serial.begin(9600);   // Initialize serial communications with the PC
  while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();      // Init SPI bus
  mfrc522.PCD_Init();   // Init MFRC522
  delay(4);       // Optional delay. Some board do need more time after init to be ready, see Readme
  mfrc522.PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
  
}

void loop() {

  if(millis()-time_out >= 5000){
  go_sleep();
  wake_up();
  time_out = millis();
}

  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  // Dump debug info about the card; PICC_HaltA() is automatically called
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

 
