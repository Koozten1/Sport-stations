#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN         9        // Пин rfid модуля RST
#define SS_PIN          10       // Пин rfid модуля SS

#define AddrBlock 62
#define TrailerBlock 63

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Объект rfid модуля
MFRC522::MIFARE_Key key;         // Объект ключа
MFRC522::StatusCode status;      // Объект статуса
static uint32_t rebootTimer = millis();

void setup() {
  Serial.begin(9600);            // Инициализация Serial
  SPI.begin();                   // Инициализация SPI
  mfrc522.PCD_Init();   // Инициализация модуля

  
  for (byte i = 0; i < 6; i++) { // Наполняем ключ
    key.keyByte[i] = 0xFF;       // Ключ по умолчанию 0xFFFFFFFFFFFF
  }

  
}



void loop() {

    if (millis() - rebootTimer >= 1000) {   
          rebootTimer = millis();               
          digitalWrite(RST_PIN, HIGH);          
          delayMicroseconds(2);                 
          digitalWrite(RST_PIN, LOW);           
          mfrc522.PCD_Init();                   
    }
    byte status;

    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    if ( ! mfrc522.PICC_ReadCardSerial())
        return;
        
    byte piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    
    if ( piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        return;
    }


    //Служебная информация
    byte dataBlock[18];                           
    uint8_t size = sizeof(dataBlock); 
    
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, TrailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        return;
    }
     
    status = mfrc522.MIFARE_Read(AddrBlock, dataBlock, &size);
    
    if (status != MFRC522::STATUS_OK) {
        return;
    }

    int sector_end = (int)dataBlock[0];
    int block_end = (int)dataBlock[1];
    int start = (int)dataBlock[2];
    int end_ = (int)dataBlock[3];
    

    for (byte i = 0; i < mfrc522.uid.size; i++) {
      Serial.print(mfrc522.uid.uidByte[i]);
    } 
    
    for(int block = 1, access_sector = 3;  block <= block_end; block++){
       if((block + 1) % 4  == 0){
          access_sector += 4;
          continue; 
       }
       
       mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, access_sector, &key, &(mfrc522.uid));
       mfrc522.MIFARE_Read(block, dataBlock, &size);

       for (int i = 0; i < 16; i++){
              if(i % 4 == 0){
                Serial.print('\n');
              }

              if(i == start && block == block_end){
                break;
              }
 
              Serial.print((int)dataBlock[i]);
              Serial.print(' ');
              
       }
    }
 
    Serial.print("\nend\n");
    mfrc522.PICC_HaltA();                              
    mfrc522.PCD_StopCrypto1();

    delay(1000);    
  
 }