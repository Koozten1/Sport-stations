#include <iarduino_RTC.h>  
#include <SPI.h>
#include <MFRC522.h>
#include <GyverPower.h>

#define RST_PIN         9           
#define SS_PIN          10 

#define pin_SW_SDA 4                                   // Назначение любого вывода Arduino для работы в качестве линии SDA программной шины I2C.
#define pin_SW_SCL 5  

void write_data();
void restart();
void set_long_sleep();
void set_timer_sleep();
bool is_master();
void signal_type(int type);
bool isSame(byte *key_uid);


iarduino_RTC watch(RTC_DS3231); 
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

int time_slipe = 5000;
bool statys = false;



void setup() {
    SPI.begin();  
    Serial.begin(9600);    
    mfrc522.PCD_Init();
    watch.begin();
    
    pinMode(5,OUTPUT);
    pinMode(8,OUTPUT);
    digitalWrite(8, HIGH);
    
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
         
    power.autoCalibrate();
    power.setSleepMode(STANDBY_SLEEP);

}

void loop() {
  power.sleepDelay(time_slipe);
  restart();
  write_data();  
  
}

//if error would be restart rfid 
void restart(){            
    digitalWrite(RST_PIN, HIGH);          
    delayMicroseconds(1);                 
    digitalWrite(RST_PIN, LOW);           
    mfrc522.PCD_Init();                     
} 
  
void signal_type(int type){
    analogWrite(6, 50);
    delay(40);
    analogWrite(6, 0);
    if (type == 1){
      for (int i = 0; i < 3; i++){
        digitalWrite(5, HIGH);
        delay(15);
        digitalWrite(5, LOW); 
        delay(5);
        }return;  
     }
     for (int i = 0; i < type; i++){
     digitalWrite(5, HIGH);
     delay(15);
     digitalWrite(5, LOW);  
     delay(5);
  }
}

void set_long_sleep(){
  time_slipe = 10000;
  statys = false;
  signal_type(5);//show signal on LND 5 times
}

void set_sort_sleep(){
    if (statys == false){
      statys = true;
      signal_type(1);
      time_slipe = 260;
      return;
    }else{
      statys = false;
      signal_type(5);//show signal on LND 5 times
      time_slipe = 5000;  
    }
}

bool isSame(byte *key_uid){
  for (int i  = 0; i <=3; i++){
      if(mfrc522.uid.uidByte[i] != key_uid[i])
        return false;}
  return true;
}

//deside is card master 
bool is_master(){
  byte m_key[4] = {0xD3, 0xDE, 0x60, 0x00};
  byte s_key[4] = {0xA3, 0x1E,  0xD3, 0x0E};
  
  if (!(isSame(m_key) || isSame(s_key))){
      return false;
  }else if(mfrc522.uid.uidByte[3] == m_key[3]){
      set_sort_sleep();
  }else if(mfrc522.uid.uidByte[3] == s_key[3]){
      set_long_sleep();
  }

  return true;
}

void write_data(){
  byte status;
  byte AddrBlock = 62;
  byte trailerBlock   = 63;
  // put your main code here, to run repeatedly:
  if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;
        
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    
    if ( piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        time_slipe = 2000;
        return;
    }

    if(!is_master() == false){ 
      return;
    }
     
    // Number first sector
    byte first_sector_set[] = {
        0x03, 0x01, 0x04, 0x07, //  sector, bloack, start, finish 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00};
        
    // Date first write
    byte first_marc_set[] = {
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00};
    

   watch.gettime("d-m-Y, H:i:s, D");
   first_marc_set[0] = byte(60);
   first_marc_set[1] = byte(watch.Hours);
   first_marc_set[2] = byte(watch.minutes);
   first_marc_set[3] = byte(watch.seconds);
   
  
  //Set ninformation about sectors
   mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
   status = mfrc522.MIFARE_Write(AddrBlock, first_sector_set, 16);
   if (status != MFRC522::STATUS_OK)
        return;
    
  mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 0x00, &key, &(mfrc522.uid));

  status = mfrc522.MIFARE_Write(0x01, first_marc_set, 16);
  if (status != MFRC522::STATUS_OK) {
        return;
  }
  signal_type(1);   
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();   
   
}
