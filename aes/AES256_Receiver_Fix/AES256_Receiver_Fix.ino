#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <SD.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include <SPI.h>
using namespace std::chrono;

#define SD_CS_PIN D8 
const size_t BLOCK_SIZE = 16;
const unsigned long TIMEOUT_MS = 100;
uint8_t *receivedData = nullptr;
size_t receivedLen = 0;
size_t bufferSize = 0;
unsigned long lastReceivedTime = 0;
int fileIndex = 0; // File index for SD card files

// AES Key and Initialization Vector (IV)
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

uint8_t iv[BLOCK_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

// AES-256 CBC Decryption Function
void aes256CbcDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], uint8_t iv[BLOCK_SIZE]) {
    AES aes;
    aes.set_key(key, 32);
    uint8_t currentIv[BLOCK_SIZE];
    memcpy(currentIv, iv, BLOCK_SIZE); // Preserve original IV

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t tempCipher[BLOCK_SIZE];
        memcpy(tempCipher, input + i, BLOCK_SIZE);

        // Decrypt block
        aes.decrypt(input + i, output + i);

        // XOR with IV to get plaintext
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            output[i + j] ^= currentIv[j];
        }

        // Update IV to current ciphertext
        memcpy(currentIv, tempCipher, BLOCK_SIZE);
    }
}

// Remove PKCS7 Padding
size_t removePadding(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t padValue = data[len - 1];
    if (padValue > BLOCK_SIZE || padValue == 0) return len; // Invalid padding
    return len - padValue;
}

// Expand Buffer for Incoming Data
bool expandBuffer(size_t additionalSize) {
    size_t newSize = receivedLen + additionalSize;
    if (newSize > bufferSize) {
        bufferSize = newSize;
        uint8_t *newBuffer = (uint8_t *)realloc(receivedData, bufferSize);
        if (!newBuffer) {
            Serial.println("Failed to allocate memory!");
            free(receivedData);
            ESP.restart(); // Restart if memory allocation fails
            return false;
        }
        receivedData = newBuffer;
    }
    return true;
}

// Process and Decrypt Data
void processData() {
    if (receivedLen == 0) return;

    // Allocate buffer for decrypted data
    uint8_t *decryptedData = (uint8_t *)malloc(receivedLen);
    if (!decryptedData) {
        Serial.println("Failed to allocate decryption buffer");
        ESP.restart(); // Restart if memory allocation fails
        return;
    }

    auto start = high_resolution_clock::now();
    aes256CbcDecrypt(receivedData, decryptedData, receivedLen, key, iv);
    auto end = high_resolution_clock::now();
    auto decryptDuration = duration_cast<microseconds>(end - start).count();

    size_t decryptedLen = removePadding(decryptedData, receivedLen);

    Serial.print("Total Received Data Size: ");
    Serial.print(decryptedLen);
    Serial.println(" Bytes");

    Serial.print("Decryption Time: ");
    Serial.print(decryptDuration);
    Serial.println(" microseconds");

    Serial.print("Decrypted Data: ");
    for (size_t i = 0; i < decryptedLen; i++) {
        Serial.print((char)decryptedData[i]);
    }
    Serial.println();

    // Save to SD Card
    if (saveDecryptedDataToSD(decryptedData, decryptedLen)) {
        // Serial.println("Decrypted data saved to SD card successfully.");
    } else {
        // Serial.println("Failed to save decrypted data to SD card.");
    }

    // Cleanup
    free(decryptedData);
    free(receivedData);
    receivedData = nullptr;
    receivedLen = 0;
    bufferSize = 0;
}

// Save Decrypted Data to SD Card
bool saveDecryptedDataToSD(uint8_t *plaintext, size_t dataLen) {
    String filename = "/aes_data_decrypted_" + String(fileIndex++) + ".txt";

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
    return true;
}

// ESP-NOW Receive Callback
void onDataReceive(uint8_t *mac, uint8_t *incomingData, uint8_t len) {
    lastReceivedTime = millis();
    if (!expandBuffer(len)) return;
    memcpy(receivedData + receivedLen, incomingData, len);
    receivedLen += len;
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("Failed to initialize SD card");
    }

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }

    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(onDataReceive);
}

void loop() {
    if (millis() - lastReceivedTime > TIMEOUT_MS && receivedLen > 0) {
        processData();
        Serial.println("------------------------------------------------");
    }
}
