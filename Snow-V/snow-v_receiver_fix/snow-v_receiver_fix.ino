#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <SD.h>
#include <chrono>
using namespace std::chrono;

// Configuration constants
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

const uint8_t iv[16] = {
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Globals for received data
uint8_t *receivedData = nullptr;
size_t totalDataLen = 0;
bool allFragmentsReceived = false;
int fileIndex = 0; // File index for saving decrypted data

// Functions for encryption and decryption
void initializeSnowV(uint32_t *LFSR, uint32_t *FSM) {
    memcpy(LFSR, key, 32);
    memcpy(LFSR + 8, iv, 16);
    memset(FSM, 0, 3 * sizeof(uint32_t));
}

void generateSnowVKeystream(uint32_t *LFSR, uint32_t *FSM, uint8_t *keystream, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t f = (FSM[0] + LFSR[0]) ^ FSM[2];
        FSM[2] = FSM[1];
        FSM[1] = FSM[0];
        FSM[0] = f;

        uint32_t s = LFSR[11];
        for (int j = 11; j > 0; j--) {
            LFSR[j] = LFSR[j - 1];
        }
        LFSR[0] = s ^ f;

        ((uint32_t *)keystream)[i / 4] = f;
    }
}

void snowVEncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len) {
    uint32_t LFSR[12], FSM[3];
    initializeSnowV(LFSR, FSM);

    uint8_t keystream[64];
    size_t i = 0;

    while (i < len) {
        generateSnowVKeystream(LFSR, FSM, keystream, 64);
        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            output[i] = input[i] ^ keystream[j];
        }
    }
}

// ESP-NOW data reception
void onDataRecv(uint8_t *mac_addr, uint8_t *incomingData, uint8_t len) {
    uint8_t fragmentNum = incomingData[0];
    bool isLast = incomingData[1];

    if (fragmentNum == 0) {
        free(receivedData);
        receivedData = (uint8_t *)malloc(15360);
        totalDataLen = 0;
    }

    if (receivedData != nullptr) {
        memcpy(receivedData + (fragmentNum * 240), incomingData + 2, len - 2);
        totalDataLen += (len - 2);

        if (isLast) {
            allFragmentsReceived = true;
        }
    } else {
        Serial.println("Memory allocation failed!");
    }
}

// Decrypt received data
uint8_t *decryptReceivedData(size_t &outLen) {
    if (!allFragmentsReceived || receivedData == nullptr) {
        return nullptr;
    }

    uint8_t *decryptedData = (uint8_t *)malloc(totalDataLen + 1);
    if (decryptedData != nullptr) {
        auto start = high_resolution_clock::now();
        snowVEncryptDecrypt(receivedData, decryptedData, totalDataLen);
        auto end = high_resolution_clock::now();
        auto encryptDuration = duration_cast<microseconds>(end - start).count();
        Serial.printf("Encryption Time: %ld microseconds\n", encryptDuration);
        decryptedData[totalDataLen] = '\0';
        outLen = totalDataLen;
    } else {
        Serial.println("Decryption buffer allocation failed!");
    }

    free(receivedData);
    receivedData = nullptr;
    totalDataLen = 0;
    allFragmentsReceived = false;

    return decryptedData;
}

// Save decrypted data to SD card
bool saveDecryptedDataToSD(const uint8_t *plaintext, size_t dataLen) {
    String filename = "/snowv_data_decrypted_" + String(fileIndex) + ".txt";
    File dataFile = SD.open(filename, FILE_WRITE);

    if (!dataFile) {
        Serial.println("Error opening file for writing");
        return false;
    }

    size_t bytesWritten = dataFile.write(plaintext, dataLen);
    dataFile.close();

    if (bytesWritten != dataLen) {
        Serial.println("Error writing to file");
        return false;
    }

    Serial.print("Data saved to ");
    Serial.println(filename);

    fileIndex++;
    return true;
}

// Process received messages
void processReceivedMessage() {
    size_t decryptedLen;
    uint8_t *decryptedData = decryptReceivedData(decryptedLen);

    if (decryptedData != nullptr) {
        Serial.print("Decrypted Message: ");
        Serial.println((char *)decryptedData);

        if (!saveDecryptedDataToSD(decryptedData, decryptedLen)) {
            Serial.println("Failed to save data to SD card");
        }

        free(decryptedData);
        Serial.println("------------------------------------------------");
    }
}

// ESP-NOW initialization
bool initESPNow() {
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(onDataRecv);
    return true;
}

// Arduino setup
void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!SD.begin(D8)) { // Initialize SD card on D8 pin
        Serial.println("SD card initialization failed!");
        return;
    }

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
    }
}

void loop() {
    processReceivedMessage();
    delay(50);
}
