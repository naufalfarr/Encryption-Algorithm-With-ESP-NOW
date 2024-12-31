#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include <SD.h>
#include <SPI.h>
#include "InputData.h"
using namespace std::chrono;

// Configuration
const int MAX_DATA_SIZE = 16384; // 16KB
const int ESP_NOW_MAX_PAYLOAD = 250;
const int CLEFIA_BLOCK_SIZE = 16;
const int CLEFIA_KEY_SIZE = 32;
const int CLEFIA_ROUNDS = 32;
const int SD_CS_PIN = D8;  // Change this to match your SD card CS pin
const int MAX_INPUT_SIZE = 16384;

// Global counter and file index
uint32_t counter = 1;
static int fileIndex = 0;

// Variables for receiving data
uint8_t* receivedData = nullptr;
size_t totalReceived = 0;
unsigned long lastReceiveTime = 0;
bool isReceiving = false;

// Forward declarations
void clefiaDecrypt(uint32_t *plaintext, const uint32_t *ciphertext, const uint32_t *rk);
void clefiaKeySchedule(uint32_t *rk, const uint8_t *key);
void clefiaF(uint32_t *dst, const uint32_t *src, int offset);

// Core CLEFIA Functions
void ICACHE_RAM_ATTR clefiaF(uint32_t *dst, const uint32_t *src, int offset) {
    uint32_t x = src[0] ^ pgm_read_con256(offset);
    uint32_t y = src[1];
    uint32_t z = pgm_read_con256(offset);

    y ^= rotr(x, 8) ^ rotl(x, 16) ^ rotl(x, 24);
    
    uint32_t temp = 0;
    temp |= ((uint32_t)pgm_read_S0((uint8_t)(y >> 24))) << 0;
    temp |= ((uint32_t)pgm_read_S1((uint8_t)(y >> 16))) << 8;
    temp |= ((uint32_t)pgm_read_S0((uint8_t)(y >> 8))) << 16;
    temp |= ((uint32_t)pgm_read_S1((uint8_t)y)) << 24;
    
    dst[0] = temp ^ z;
    dst[1] = y;
    
    yield();
}

void ICACHE_RAM_ATTR clefiaKeySchedule(uint32_t *rk, const uint8_t *key) {
    // Same as in the sender code
    uint32_t L[8], KL[4], KR[4];
    
    for (int i = 0; i < 8; i++) {
        L[i] = ((uint32_t)key[4*i+3] << 24) | 
               ((uint32_t)key[4*i+2] << 16) |
               ((uint32_t)key[4*i+1] << 8) | 
               ((uint32_t)key[4*i]);
        yield();
    }
    
    memcpy(KL, L, 16);
    memcpy(KR, L + 4, 16);
    
    rk[0] = KL[0];
    rk[1] = KL[1];
    rk[2] = KR[0];
    rk[3] = KR[1];
    
    for (int i = 0; i < CLEFIA_ROUNDS / 4; i++) {
        uint32_t T[4];
        memcpy(T, KL, 16);
        
        clefiaF(&T[0], &T[2], i*4);
        clefiaF(&T[2], &T[0], i*4+2);
        
        for (int j = 0; j < 4; j++) {
            rk[i*4 + 4 + j] = T[j];
        }
        
        if (i % 2 == 0) {
            for (int j = 0; j < 4; j++) {
                KL[j] ^= rotl(T[j], 15);
            }
        } else {
            for (int j = 0; j < 4; j++) {
                KL[j] ^= rotl(T[j], 17);
            }
        }
        
        yield();
    }
    
    rk[CLEFIA_ROUNDS + 0] = KL[2];
    rk[CLEFIA_ROUNDS + 1] = KL[3];
}

void ICACHE_RAM_ATTR clefiaDecrypt(uint32_t *plaintext, const uint32_t *ciphertext, const uint32_t *rk) {
    uint32_t L[2], R[2], T[2];
    
    // Initial whitening (reverse of encryption)
    L[0] = ciphertext[0] ^ rk[CLEFIA_ROUNDS + 0];
    L[1] = ciphertext[1] ^ rk[CLEFIA_ROUNDS + 1];
    R[0] = ciphertext[2] ^ rk[2];
    R[1] = ciphertext[3] ^ rk[3];
    
    // Core decryption rounds (reverse order)
    for (int i = CLEFIA_ROUNDS - 2; i >= 0; i -= 2) {
        clefiaF(T, L, i + 4);
        T[0] ^= R[0];
        T[1] ^= R[1];
        
        memcpy(R, L, 8);
        memcpy(L, T, 8);
        
        if (i % 8 == 0) yield();
    }
    
    // Final whitening (reverse)
    plaintext[0] = L[0] ^ rk[0];
    plaintext[1] = L[1] ^ rk[1];
    plaintext[2] = R[0];
    plaintext[3] = R[1];
}

// Block decryption
void decryptBlock(uint8_t* output, const uint8_t* input, const uint32_t* rk) {
    uint32_t block[4];
    
    for (int i = 0; i < 4; i++) {
        block[i] = ((uint32_t)input[4*i+3] << 24) |
                  ((uint32_t)input[4*i+2] << 16) |
                  ((uint32_t)input[4*i+1] << 8) |
                  ((uint32_t)input[4*i]);
    }
    
    clefiaDecrypt(block, block, rk);
    
    for (int i = 0; i < 4; i++) {
        output[4*i] = block[i] & 0xFF;
        output[4*i+1] = (block[i] >> 8) & 0xFF;
        output[4*i+2] = (block[i] >> 16) & 0xFF;
        output[4*i+3] = (block[i] >> 24) & 0xFF;
    }
    
    ESP.wdtFeed();
}


// Transmission control
struct PacketHeader {
  uint16_t sequenceNumber;
  uint16_t totalPackets;
  uint16_t payloadSize;
};

// Global variables
uint8_t* decryptionBuffer = nullptr;
uint32_t* roundKeys = nullptr;
size_t totalReceivedSize = 0;
uint16_t expectedPackets = 0;
uint16_t receivedPackets = 0;
bool* receivedPacketFlags = nullptr;

// SD Card functions
bool initSDCard() {
    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("SD Card initialization failed!");
        return false;
    }
    Serial.println("SD Card initialized successfully");
    return true;
}

bool saveDecryptedDataToSD(uint8_t* plaintext, size_t dataLen) {
    String filename = "/clefia_data_decrypted_" + String(fileIndex) + ".txt";
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

// Helper functions
inline uint32_t rotl(uint32_t x, int s) {
    return (x << s) | (x >> (32 - s));
}

inline uint32_t rotr(uint32_t x, int s) {
    return (x >> s) | (x << (32 - s));
}

inline uint32_t pgm_read_con256(int index) {
    return pgm_read_dword(&CLEFIA_CONSTANTS[index]);
}

inline uint8_t pgm_read_S0(int index) {
    return pgm_read_byte(&clefia_s0[index]);
}

inline uint8_t pgm_read_S1(int index) {
    return pgm_read_byte(&clefia_s1[index]);
}


// Process received data
void processReceivedData() {
    if (!receivedData || !decryptionBuffer || totalReceivedSize == 0) {
        return;
    }

    // Generate round keys
    static const uint8_t key[CLEFIA_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    auto decryptionStart = std::chrono::high_resolution_clock::now();
    
    clefiaKeySchedule(roundKeys, key);

    // Decrypt data in blocks
    size_t paddedSize = ((totalReceivedSize + CLEFIA_BLOCK_SIZE - 1) / CLEFIA_BLOCK_SIZE) * CLEFIA_BLOCK_SIZE;
    
    for (size_t i = 0; i < paddedSize; i += CLEFIA_BLOCK_SIZE) {
        decryptBlock(decryptionBuffer + i, receivedData + i, roundKeys);
        yield();
    }

    auto decryptionEnd = std::chrono::high_resolution_clock::now();
    auto decryptionDuration = std::chrono::duration_cast<std::chrono::microseconds>(decryptionEnd - decryptionStart).count();
    
    Serial.print(F("Decryption time (microseconds): "));
    Serial.println(decryptionDuration);
    
    // Print decrypted data as text
    Serial.print(F("Decrypted text: "));
    Serial.write(decryptionBuffer, totalReceivedSize);
    Serial.println();

    // Save decrypted data to SD card
    if (saveDecryptedDataToSD(decryptionBuffer, totalReceivedSize)) {
        Serial.println("Data successfully saved to SD card");
    } else {
        Serial.println("Failed to save data to SD card");
    }
    
    // Reset for next transmission
    totalReceivedSize = 0;
    receivedPackets = 0;
    expectedPackets = 0;
    
    if (receivedPacketFlags) {
        free(receivedPacketFlags);
        receivedPacketFlags = nullptr;
    }

    // Update counter
    counter++;
}

bool allocateBuffers(size_t size) {
    freeBuffers();
    
    size_t alignedSize = ((size + CLEFIA_BLOCK_SIZE - 1) / CLEFIA_BLOCK_SIZE) * CLEFIA_BLOCK_SIZE;
    
    // Properly allocate memory using new
    receivedData = new uint8_t[alignedSize];
    decryptionBuffer = new uint8_t[alignedSize];
    roundKeys = new uint32_t[CLEFIA_ROUNDS + 4];
    
    if (!receivedData || !decryptionBuffer || !roundKeys) {
        freeBuffers();
        return false;
    }
    
    return true;
}
void freeBuffers() {
    if (receivedData != nullptr) {
        delete[] receivedData;
        receivedData = nullptr;
    }
    if (decryptionBuffer != nullptr) {
        delete[] decryptionBuffer;
        decryptionBuffer = nullptr;
    }
    if (roundKeys != nullptr) {
        delete[] roundKeys;
        roundKeys = nullptr;
    }
    if (receivedPacketFlags != nullptr) {
        delete[] receivedPacketFlags;
        receivedPacketFlags = nullptr;
    }
    
    ESP.wdtFeed();
    delay(0);
}
// ESP-NOW callback

void ICACHE_RAM_ATTR OnDataRecv(uint8_t *mac_addr, uint8_t *data, uint8_t len) {
    lastReceiveTime = millis();
    if (!isReceiving) {
        isReceiving = true;
        totalReceived = 0;
    }

    if (len < sizeof(PacketHeader)) return;
    
    PacketHeader* header = (PacketHeader*)data;
    
    // Initialize for new transmission
    if (header->sequenceNumber == 0) {
        size_t totalSize = header->totalPackets * (ESP_NOW_MAX_PAYLOAD - sizeof(PacketHeader));
        if (!allocateBuffers(totalSize)) {
            Serial.println(F("Failed to allocate memory"));
            return;
        }
        
        expectedPackets = header->totalPackets;
        receivedPacketFlags = new bool[expectedPackets]();  // Changed to use new operator
        if (!receivedPacketFlags) {
            Serial.println(F("Failed to allocate packet flags"));
            return;
        }
    }
    
    // Store received data
    if (header->sequenceNumber < expectedPackets && !receivedPacketFlags[header->sequenceNumber]) {
        size_t offset = header->sequenceNumber * (ESP_NOW_MAX_PAYLOAD - sizeof(PacketHeader));
        memcpy(receivedData + offset, data + sizeof(PacketHeader), header->payloadSize);
        
        receivedPacketFlags[header->sequenceNumber] = true;
        receivedPackets++;
        
        if (header->sequenceNumber == header->totalPackets - 1) {
            totalReceivedSize = offset + header->payloadSize;
        }
    }
    
    // Process complete transmission
    if (receivedPackets == expectedPackets) {
        processReceivedData();
        isReceiving = false;
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial) { yield(); }
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    // Initialize SD Card
    if (!initSDCard()) {
        Serial.println("Warning: SD Card initialization failed!");
    }
    
    if (esp_now_init() != 0) {
        Serial.println(F("ESP-NOW init failed"));
        return;
    }
    
    esp_now_set_self_role(ESP_NOW_ROLE_SLAVE);
    esp_now_register_recv_cb(OnDataRecv);
    
    Serial.println(F("Setup complete"));
    Serial.print(F("MAC Address: "));
    Serial.println(WiFi.macAddress());
}

void loop() {
    // Check for timeout in receiving data
    if (isReceiving && (millis() - lastReceiveTime > 5000)) { // 5 second timeout
        Serial.println("Reception timeout - resetting");
        isReceiving = false;
        totalReceived = 0;
    }
    yield();
}