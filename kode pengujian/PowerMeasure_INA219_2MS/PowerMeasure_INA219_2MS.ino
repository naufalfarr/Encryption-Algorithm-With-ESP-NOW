#include <Adafruit_INA219.h>

Adafruit_INA219 ina219;

const unsigned long SERIAL_BAUD_RATE = 115200;
const unsigned long TARGET_INTERVAL_MS = 2; 

unsigned long lastMeasurementTime = 0;

void setup() {
  Serial.begin(SERIAL_BAUD_RATE);
  while (!Serial) {
    ; 
  }

  if (!ina219.begin()) {
    Serial.println(F("Failed to find INA219 chip"));
    while (1) { }
  }
}

void loop() {
  unsigned long currentTime = millis();
  if (currentTime - lastMeasurementTime >= TARGET_INTERVAL_MS) {
    float power_mW = ina219.getPower_mW();
    float voltage_v = ina219.getBusVoltage_V();
    Serial.print(currentTime);
    Serial.print(',');
    Serial.print(power_mW, 4); 
    Serial.print('\n');
    lastMeasurementTime = currentTime;
  }
}