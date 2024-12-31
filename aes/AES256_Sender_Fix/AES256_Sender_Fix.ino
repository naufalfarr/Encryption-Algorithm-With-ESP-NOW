#include <ESP8266WiFi.h>
#include <espnow.h>
#include <Crypto.h>
#include <AES.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "PlaintextData.h"
using namespace std::chrono;

const size_t BLOCK_SIZE = 16;
const unsigned long TIMEOUT_MS = 100;

// 256-bit AES Key (32 bytes)
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Initialization Vector (IV) - 16 bytes
uint8_t iv[BLOCK_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

// Transmission State Variables
size_t totalChunks = 0;
size_t chunksAcked = 0;
bool allChunksSent = false;
bool status = false;

// PKCS7 Padding
void applyPadding(uint8_t *data, size_t len, size_t paddedLen) {
    uint8_t padValue = paddedLen - len;
    for (size_t i = len; i < paddedLen; ++i) {
        data[i] = padValue;
    }
}

// AES-256 CBC Encryption
void aes256CbcEncrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], uint8_t iv[BLOCK_SIZE]) {
    AES aes;
    aes.set_key(key, 32);
    uint8_t currentIv[BLOCK_SIZE];
    memcpy(currentIv, iv, BLOCK_SIZE); // Preserves original IV

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        // XOR with IV (or previous ciphertext)
        for (size_t j = 0; j < BLOCK_SIZE; ++j) {
            output[i + j] = input[i + j] ^ currentIv[j];
        }
        // Encrypt block
        aes.encrypt(output + i, output + i);

        // Update IV to current ciphertext
        memcpy(currentIv, output + i, BLOCK_SIZE);
    }
}

// Function to encrypt a message
uint8_t* encryptMessage(const char *plaintext, size_t &encryptedLen, unsigned long &encryptionTime) {
    size_t messageLen = strlen(plaintext);
    size_t paddedLen = (messageLen + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
    encryptedLen = paddedLen;

    uint8_t *ciphertext = (uint8_t *)malloc(paddedLen);
    if (!ciphertext) {
        Serial.println("Failed to allocate encryption buffer");
        return nullptr;
    }

    // Copy data to buffer and apply padding
    memcpy(ciphertext, plaintext, messageLen);
    applyPadding(ciphertext, messageLen, paddedLen);

    // Encrypt the data
    auto start = high_resolution_clock::now();
    aes256CbcEncrypt(ciphertext, ciphertext, paddedLen, key, iv);
    auto end = high_resolution_clock::now();
    delay(2000);

    encryptionTime = duration_cast<microseconds>(end - start).count();

    return ciphertext;
}

// Function to send encrypted data
bool sendEncryptedData(uint8_t *data, size_t len) {
    totalChunks = (len + 249) / 250; // Calculate total chunks
    chunksAcked = 0;
    allChunksSent = false;

    for (size_t i = 0; i < len; i += 250) {
        size_t chunkSize = min((size_t)250, len - i);
        if (esp_now_send(nullptr, data + i, chunkSize) != 0) {
            Serial.println("Error sending data");
            return false;
        }
        delay(10); // Avoid overwhelming the receiver
    }

    // Wait for all chunks to be acknowledged
    unsigned long startTime = millis();
    while (!allChunksSent && (millis() - startTime < TIMEOUT_MS)) {
        delay(10);
    }

    return allChunksSent;
}

// Transmission Callback
void onSend(uint8_t *mac_addr, uint8_t deliveryStatus) {
    if (deliveryStatus == 0) {  // If transmission is successful
        status = true;
        chunksAcked++; // Increment ACK counter
    } else {
        status = false;
    }

    // Check if all chunks have been acknowledged
    if (chunksAcked == totalChunks && deliveryStatus == 0) {
        allChunksSent = true;
        Serial.println("All chunks sent successfully");
    }
    // else if (allChunksSent == false) {
    //   Serial.println("Chunks failed to send");
    // }
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (esp_now_init() != 0) {
        Serial.println("Error initializing ESP-NOW");
        ESP.restart();
    }

    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);
    esp_now_register_send_cb(onSend); // Register the send callback

    // Set peer MAC address of the receiver
    uint8_t receiverMac[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};
    esp_now_add_peer(receiverMac, ESP_NOW_ROLE_SLAVE, 1, NULL, 0);
}

void loop() {
    
    size_t plaintextSize = strlen(plaintextSets[1]);
    size_t encryptedLen = 0;
    unsigned long encryptionTime = 0;

    // Encrypt the message
    uint8_t *ciphertext = encryptMessage(plaintextSets[1], encryptedLen, encryptionTime);

    if (ciphertext != nullptr) {
        Serial.print("Plaintext:  ");
        Serial.println(plaintextSets[1]);        
        Serial.print("Encrypted Data: ");
        for (size_t i = 0; i < encryptedLen; i++) {
            Serial.print(ciphertext[i], HEX); // Print each byte in hexadecimal
        }
        Serial.println(); // End the line

        Serial.print("Plaintext Size: ");
        Serial.print(plaintextSize);
        Serial.println(" Byte (B)");
        Serial.print("Encryption Time: ");
        Serial.print(encryptionTime);
        Serial.println(" microseconds (μs)");

        Serial.print("Total Chunks: ");
        Serial.println(totalChunks);

        // Send encrypted data
        sendEncryptedData(ciphertext, encryptedLen);
        if (allChunksSent == false) {
        Serial.println("Chunks failed to send");
    };
        // Free dynamically allocated memory
        free(ciphertext);
    }

    delay(2000); // Send data every 2 seconds
    Serial.println("------------------------------------------------");
}
