#include <iarduino_RTC.h>  
#include <SPI.h>
#include <MFRC522.h>
#include <GyverPower.h>

#define RST_PIN 9           
#define SS_PIN 10 

#define pin_SW_SDA 5                                   // Назначение любого вывода Arduino для работы в качестве линии SDA программной шины I2C.
#define pin_SW_SCL 4  

#define AddrBlock 62
#define TrailerBlock 63


void write_data();
void go_sleep();
void wake_up();
void set_timer_sleep();
bool is_sleep_card();
void send_signal();
bool is_Same(byte *key_uid);


iarduino_RTC watch(RTC_DS3231); 
MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

uint32_t  time_out = millis();
uint32_t  time_wait = millis();

int time_slipe = 260;
bool statys = false;



void setup() {
    SPI.begin();     
    mfrc522.PCD_Init();
    watch.begin();
    
    pinMode(5, OUTPUT);
    pinMode(8, OUTPUT);
    digitalWrite(8, HIGH);
    
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
         
    power.autoCalibrate();
    power.setSleepMode(STANDBY_SLEEP);

    send_signal();

}

void loop() {
    if(millis() - time_out >= time_slipe){
        go_sleep();
        wake_up();
        time_out = millis();
    }
    write_data();  
    
}

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
} 
  
void send_signal(){
    analogWrite(3, 20);
    delay(40);
    analogWrite(3, 0);
    
    for (int i = 0; i < 3; i++){
        digitalWrite(2, HIGH);
        delay(15);
        digitalWrite(2, LOW); 
        delay(5);
    }
}

void set_sort_sleep(){
    if (!statys){
        time_slipe = 260;
    }else{
        time_slipe = 5000;  
    }

    statys = !statys;
    send_signal();
}

bool is_Same(byte *key_uid){
    for (int i = 0; i <= 3; i++){
        if(mfrc522.uid.uidByte[i] != key_uid[i])
            return false;
    }
    return true;
}

bool is_sleep_card(){
    byte card_key[] = {0xD3, 0xDE, 0x60, 0x00};
    
    if (is_Same(card_key)){
        set_sort_sleep();
    }else{
        return false;
    }

    return true;
}

void write_data(){
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

    
    if(is_sleep_card()){ 
      return;
    }

    //Служебная информация
    byte dataBlock[18];                           
    //Информация с отметками
    byte dataBlockMain[18];        

    uint8_t size = sizeof(dataBlock); 
    
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, TrailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        return;
    }
     
    status = mfrc522.MIFARE_Read(AddrBlock, dataBlock, &size);
    if (status != MFRC522::STATUS_OK) {
        return;
    }

    if((int)dataBlock[4] == 1) return;

    
    int ass_sector = (int)dataBlock[0];
    int sector = (int)dataBlock[1];
    int start = (int)dataBlock[2];
    int end_ = (int)dataBlock[3];

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, ass_sector, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        return;
    }
     
    status = mfrc522.MIFARE_Read(sector, dataBlockMain, &size);
    if (status != MFRC522::STATUS_OK) {
        return;
    }
   
    if(start == 16){
      start = 0; 
      end_ = 4;
      sector++;
      
      if((sector+1) % 4 ==  0){
        sector++;  
        ass_sector += 4;  
      }  
    }

    //Хранит значения блока
    byte dataValues[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    for (int i = 0; i < start; i++){
        dataValues[i] = dataBlockMain[i];
    } 
    
    watch.gettime("d-m-Y, H:i:s, D");
    dataValues[start] = byte(40);
    dataValues[start + 1] = byte(watch.Hours);
    dataValues[start + 2] = byte(watch.minutes);
    dataValues[start + 3] = byte(watch.seconds);

    // Служебная информация  в 63 блоке
    byte dataToWrite[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
    };

    dataToWrite[0] = (byte)ass_sector;
    dataToWrite[1] = (byte)sector;
    dataToWrite[2] = (byte)start + 4;
    dataToWrite[3] = (byte)end_ + 4;
   
   
    if(sector == 62){
        return; 
    }
  
   
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, TrailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        return;
    }

    status = mfrc522.MIFARE_Write(AddrBlock, dataToWrite, 16);
    if (status != MFRC522::STATUS_OK) {
        return;
    }

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, ass_sector, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        return;
    }

    status = mfrc522.MIFARE_Write(sector, dataValues, 16);
    if (status != MFRC522::STATUS_OK)
      return;
  
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();   

    send_signal(); 

}