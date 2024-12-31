#include <ESP8266WiFi.h>
#include <espnow.h>
#include <cstring>
#include <stdint.h>
#include <chrono>
#include "PlaintextData.h"
using namespace std::chrono;

uint8_t receiverMAC[] = {0x84, 0xF3, 0xEB, 0x05, 0x50, 0xB7};

// Global Configuration Constants
const size_t MAX_CHUNK_SIZE = 250;  
const size_t MAX_INPUT_SIZE = 16384; 

// 256 bit key
uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

//nonce
uint8_t nonce[12];

// Transmission State Variables
size_t totalChunks = 0;
size_t chunksAcked = 0;
bool allChunksSent = false;
bool status = false;
uint32_t counter = 1;

// Rotasi/menggeser bit ke kiri dan ke kanan
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

// Fungsi ChaCha quarter round (penjumlahan dan xor)
void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = ROTL(d, 16);
    c += d; b ^= c; b = ROTL(b, 12);
    a += b; d ^= a; d = ROTL(d, 8);
    c += d; b ^= c; b = ROTL(b, 7);
}

// Fungsi untuk menghasilkan keystream 64-byte
void chacha20Block(uint32_t out[16], const uint32_t in[16]) {
    memcpy(out, in, sizeof(uint32_t) * 16); //copy state awal ke output
    for (int i = 0; i < 10; i++) {
        //column round      
        quarterRound(out[0], out[4], out[ 8], out[12]);
        quarterRound(out[1], out[5], out[ 9], out[13]);
        quarterRound(out[2], out[6], out[10], out[14]);
        quarterRound(out[3], out[7], out[11], out[15]);
        //diagonal round        
        quarterRound(out[0], out[5], out[10], out[15]);
        quarterRound(out[1], out[6], out[11], out[12]);
        quarterRound(out[2], out[7], out[ 8], out[13]);
        quarterRound(out[3], out[4], out[ 9], out[14]);
    }
    for (int i = 0; i < 16; i++) {
        out[i] += in[i];
    }
}

// Fungsi enkripsi XOR, bisa digunakan untuk enkripsi dan dekripsi
void chacha20EncryptDecrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16] = {
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, // Constant
        ((uint32_t *)key)[0], ((uint32_t *)key)[1], ((uint32_t *)key)[2], ((uint32_t *)key)[3], 
        ((uint32_t *)key)[4], ((uint32_t *)key)[5], ((uint32_t *)key)[6], ((uint32_t *)key)[7], 
        counter, ((uint32_t *)nonce)[0], ((uint32_t *)nonce)[1], ((uint32_t *)nonce)[2]
    };

    uint8_t block[64]; 
    size_t i = 0;

    while (i < len) { 
        uint32_t outputBlock[16]; //buffer keystream
        chacha20Block(outputBlock, state); //generate keystream
        state[12]++;  // Increment counter

        for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
            block[j] = ((uint8_t *)outputBlock)[j];
            output[i] = input[i] ^ block[j];  // XOR dengan keystream
        }
    }
}

// Encryption Function
uint8_t* encryptMessage(const char* plaintext, size_t& encryptedLen, uint64_t& encryptionTime) {
    size_t len = strlen(plaintext);

    // Validasi ukuran input
    if (len > MAX_INPUT_SIZE) {
        Serial.println("Input size exceeds maximum buffer size!");
        return nullptr;
    }

    // Alokasikan memori untuk ciphertext (plaintext + nonce)
    size_t totalSize = len + sizeof(nonce);
    uint8_t* ciphertext = (uint8_t*)malloc(totalSize);
    if (ciphertext == nullptr) {
        Serial.println("Memory allocation failed!");
        return nullptr;
    }

    // Generate nonce dinamis
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = random(0, 256);
    }

    auto start = high_resolution_clock::now();
    
    // Encrypt plaintext
    chacha20EncryptDecrypt((const uint8_t*)plaintext, ciphertext + sizeof(nonce), len, key, nonce, counter);

    auto end = high_resolution_clock::now();
    encryptionTime = duration_cast<microseconds>(end - start).count(); 

    // Salin nonce ke awal ciphertext
    memcpy(ciphertext, nonce, sizeof(nonce));

    Serial.print("Encryption Time: ");
    Serial.print(encryptionTime);
    Serial.println(" microseconds (μs)");
    Serial.print("Plaintext: ");
    Serial.println(plaintext);
    Serial.print("Encrypted Data (HEX): ");
    for (size_t i = 0; i < totalSize; ++i) {
        Serial.print(ciphertext[i], HEX);
    }

    // Serial.print("Nonce: ");
    // for (size_t i = 0; i < sizeof(nonce); ++i) {
    //     Serial.print(nonce[i], HEX);
    // }
    
    Serial.println();

    encryptedLen = totalSize;
    return ciphertext;
    delay(2000);
}

// Transmission Callback
void onSend(uint8_t *mac_addr, uint8_t deliveryStatus) {
    if (deliveryStatus == 0) {  // Jika terkirim sukses
        status = true;
        chunksAcked++;  // Tambah counter ACK
    } else {
        status = false;
    }

    // Cek jika semua chunk sudah mendapat ACK
    if (chunksAcked == totalChunks && deliveryStatus == 0) {
        allChunksSent = true;
        Serial.println("All chunks sent successfully");
    }  
}

// ESP-NOW Initialization
bool initESPNow() {
    if (esp_now_init() != 0) {  // ESP8266 menggunakan 0 sebagai indikator sukses
        Serial.println("Error initializing ESP-NOW");
        return false;
    }
    esp_now_set_self_role(ESP_NOW_ROLE_CONTROLLER);  // Set peran sender
    esp_now_register_send_cb(onSend);
    return true;
}

// Pairing with Receiver
bool pairWithPeer() {
    if (esp_now_is_peer_exist(receiverMAC)) {
        return true;  // Peer sudah ada
    }

    if (esp_now_add_peer(receiverMAC, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != 0) {
        Serial.println("Failed to add peer");
        return false;
    }
    Serial.println("Pairing successful");
    return true;
}

// Send Encrypted Message in Chunks
bool sendEncryptedData(uint8_t* ciphertext, size_t len) {
    totalChunks = (len + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    Serial.print("Total Chunks: ");
    Serial.println(totalChunks);

    chunksAcked = 0;  // Reset counter ACK
    allChunksSent = false;

    for (size_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
        size_t offset = chunkIndex * MAX_CHUNK_SIZE;
        size_t chunkSize = min((size_t)MAX_CHUNK_SIZE, len - offset);

        uint8_t sendStatus = esp_now_send(receiverMAC, ciphertext + offset, chunkSize);
        if (status == false) {
            Serial.println("Chunk Send Failed");
            return false;
        }

        delay(10);  // Jeda agar tidak overload
    }

    return true;
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);

    if (!initESPNow()) {
        Serial.println("ESP-NOW initialization failed");
        ESP.restart();
    }

    if (!pairWithPeer()) {
        Serial.println("Peer pairing failed");
        ESP.restart();
    }
}

void loop() {
    size_t encryptedLen = 0;
    uint64_t encryptionTime = 0;
    
    // Encrypt the message
    uint8_t* ciphertext = encryptMessage(plaintextSets[2], encryptedLen, encryptionTime);
    
    if (ciphertext != nullptr) {
        // Send encrypted data
        if (sendEncryptedData(ciphertext, encryptedLen)) {
            // Serial.println("Message sent successfully");
        }
        
        // Free dynamically allocated memory
        free(ciphertext);
    }
    
    Serial.println("------------------------------------------------");
    delay(2000);     
}