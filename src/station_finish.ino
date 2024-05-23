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
    
    if(is_sleep_card()) 
      return;
    
    //Считанные данные
    byte dataBlock[18];       
    //Массив           
    byte dataHead[16];

    uint8_t size = sizeof(dataBlock);                         
       
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, TrailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) { 
        return;
    }
     
    status = mfrc522.MIFARE_Read(AddrBlock, dataBlock, &size);

    if (status != MFRC522::STATUS_OK) {
        return;
    }

    for(int i = 0; i < 16; i++){
      dataHead[i] = dataBlock[i];    
    }

    if (dataHead[4] == 1) return;
    
    dataHead[4] = 1;
    
    if (mfrc522.MIFARE_Write(AddrBlock, dataHead, 16) != MFRC522::STATUS_OK) {            
        return;
    }
       
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();  
    send_signal();

    time_wait = millis();
}