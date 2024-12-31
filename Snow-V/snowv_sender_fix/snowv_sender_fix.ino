#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "PlaintextData.h"
using namespace std::chrono;

const uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7}; // MAC address
bool status;

// 256-bit (32-byte) key
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// 128-bit (16-byte) iv
const uint8_t iv[16] = {
    0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint32_t counter = 1;

// Initialize SNOW-V state
void initializeSnowV(uint32_t *LFSR, uint32_t *FSM) {
    memcpy(LFSR, key, 32);
    memcpy(LFSR + 8, iv, 16);
    memset(FSM, 0, 3 * sizeof(uint32_t));
}

// Generate keystream
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

// Encrypt/Decrypt function
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

uint8_t* encryptMessage(const char *plaintext, size_t &len) {
    len = strlen(plaintext);
    uint8_t *ciphertext = new uint8_t[len];
    
    // Measure encryption time
    auto start = high_resolution_clock::now();
    snowVEncryptDecrypt((const uint8_t *)plaintext, ciphertext, len);
    auto end = high_resolution_clock::now();
    delay(2000);

    // Calculate and print encryption time
    auto encryptDuration = duration_cast<microseconds>(end - start).count();
    Serial.printf("Encryption Time: %ld microseconds\n", encryptDuration);
    Serial.printf("Plaintext Size: %d bytes\n", len);

    Serial.print("Plaintext: ");
    Serial.println(plaintext);

    // Print the ciphertext in hexadecimal format
    Serial.print("Encrypted Data: ");
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", ciphertext[i]); // Print each byte in hexadecimal
    }
    Serial.println(); // End the line after printing all bytes

    return ciphertext;
}

// Send encrypted fragments
void sendEncryptedFragments(const uint8_t *ciphertext, size_t len) {
    size_t offset = 0;
    uint8_t fragmentNum = 0;
    size_t totalChunks = 0;

    while (offset < len) {
        size_t chunkSize = (len - offset > 240) ? 240 : (len - offset);
        bool isLast = (offset + chunkSize >= len);

        sendFragment(ciphertext + offset, chunkSize, fragmentNum++, isLast);
        offset += chunkSize;
        totalChunks++;
        delay(1);
    }

    if (status) {
        Serial.println("Sent successfully");
        Serial.printf("Total chunks sent: %d\n", totalChunks);
    } else {
        Serial.println("Send Failed");
    }
}

// Fragment sender function
void sendFragment(const uint8_t *data, size_t len, uint8_t fragmentNum, bool isLast) {
    uint8_t buffer[250];
    buffer[0] = fragmentNum;
    buffer[1] = isLast ? 1 : 0;
    memcpy(buffer + 2, data, len);

    if (esp_now_send((uint8_t *)receiverMAC, buffer, len + 2) != 0) {
        // Serial.println("Error sending fragment");
    }
}

bool initESPNow() {
    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    esp_now_register_send_cb(onSend);
    return true;
}

void onSend(uint8_t *mac_addr, uint8_t sendStatus) {
      if (sendStatus == 0) { 
      status = 1;
    } else {
        status = 0;
    }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        ESP.restart();
    }
}

void loop() {
    size_t len;
    uint8_t *ciphertext = encryptMessage(plaintextSets[1], len);
    sendEncryptedFragments(ciphertext, len);
    delete[] ciphertext;

    Serial.println("------------------------------------------------");
    delay(2000);
}
