// Full sketch: TOUCH Morse -> AES-128-CBC (PKCS7) -> Base64 output (ENC:...)
// Also sent to HC-05 via Serial2 (PA2/PA3 on STM32 Blue Pill)
// OLED: SH1106 128x64 via U8g2

#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include <stdint.h>
#include <string.h>
#include <Wire.h>
#include <U8g2lib.h>

// -------------------------- OLED SETUP --------------------------
U8G2_SH1106_128X64_NONAME_F_HW_I2C u8g2(
  U8G2_R0, /* reset=*/ U8X8_PIN_NONE
);

// -------------------------- BEGIN tiny-AES-c (AES CBC) --------------------------

typedef uint8_t state_t;

static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t Rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

static void KeyExpansion(const uint8_t* key, uint8_t roundKey[176]) {
  for (int i = 0; i < 16; ++i) roundKey[i] = key[i];
  int bytesGenerated = 16;
  int rconIter = 1;
  uint8_t temp[4];

  while (bytesGenerated < 176) {
    for (int i = 0; i < 4; ++i) temp[i] = roundKey[bytesGenerated - 4 + i];
    if (bytesGenerated % 16 == 0) {
      uint8_t t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t;
      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];
      temp[0] = temp[0] ^ Rcon[rconIter++];
    }
    for (int i = 0; i < 4; ++i) {
      roundKey[bytesGenerated] = roundKey[bytesGenerated - 16] ^ temp[i];
      ++bytesGenerated;
    }
  }
}

static void SubBytes(uint8_t state[16]) {
  for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

static void ShiftRows(uint8_t state[16]) {
  uint8_t temp[16];
  temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
  temp[1] = state[5]; temp[5] = state[9]; temp[9] = state[13]; temp[13] = state[1];
  temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
  temp[3] = state[15]; temp[7] = state[3]; temp[11] = state[7]; temp[15] = state[11];
  for (int i = 0; i < 16; ++i) state[i] = temp[i];
}

static uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static void MixColumns(uint8_t state[16]) {
  for (int i = 0; i < 4; ++i) {
    int col = i * 4;
    uint8_t a0 = state[col + 0];
    uint8_t a1 = state[col + 1];
    uint8_t a2 = state[col + 2];
    uint8_t a3 = state[col + 3];

    uint8_t r0 = (uint8_t)( (uint8_t)(xtime(a0)) ^ (uint8_t)(xtime(a1) ^ a1) ^ a2 ^ a3 );
    uint8_t r1 = (uint8_t)( a0 ^ (uint8_t)(xtime(a1)) ^ (uint8_t)(xtime(a2) ^ a2) ^ a3 );
    uint8_t r2 = (uint8_t)( a0 ^ a1 ^ (uint8_t)(xtime(a2)) ^ (uint8_t)(xtime(a3) ^ a3) );
    uint8_t r3 = (uint8_t)( (uint8_t)(xtime(a0) ^ a0) ^ a1 ^ a2 ^ (uint8_t)(xtime(a3)) );

    state[col + 0] = r0;
    state[col + 1] = r1;
    state[col + 2] = r2;
    state[col + 3] = r3;
  }
}

static void AddRoundKey(uint8_t state[16], const uint8_t* roundKey) {
  for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

static void AES_encryptBlock(uint8_t *state, const uint8_t roundKey[176]) {
  AddRoundKey(state, roundKey);
  for (int round = 1; round <= 9; ++round) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKey + round * 16);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKey + 10 * 16);
}

static void AES_CBC_encrypt_buffer(uint8_t* buf, uint32_t length, const uint8_t* key, uint8_t iv[16]) {
  uint8_t roundKey[176];
  KeyExpansion(key, roundKey);
  uint8_t prevBlock[16];
  for (int i = 0; i < 16; ++i) prevBlock[i] = iv[i];

  for (uint32_t i = 0; i < length; i += 16) {
    uint8_t block[16];
    for (int j = 0; j < 16; ++j) block[j] = buf[i + j] ^ prevBlock[j];
    AES_encryptBlock(block, roundKey);
    for (int j = 0; j < 16; ++j) {
      buf[i + j] = block[j];
      prevBlock[j] = block[j];
    }
  }
  for (int i = 0; i < 16; ++i) iv[i] = prevBlock[i];
}

// -------------------------- END tiny-AES-c (AES CBC) --------------------------


// -------------------------- BEGIN base64 encode (fixed padding) --------------------------

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode_chars(const uint8_t *inBuf, int inLen, char *out) {
  int outLen = 0;
  int i = 0;

  while (i < inLen) {
    int remain = inLen - i;

    uint8_t a = inBuf[i++];
    uint8_t b = (remain > 1) ? inBuf[i++] : 0;
    uint8_t c = (remain > 2) ? inBuf[i++] : 0;

    uint32_t triple = (a << 16) | (b << 8) | c;

    out[outLen++] = b64chars[(triple >> 18) & 0x3F];
    out[outLen++] = b64chars[(triple >> 12) & 0x3F];
    out[outLen++] = (remain > 1) ? b64chars[(triple >> 6) & 0x3F] : '=';
    out[outLen++] = (remain > 2) ? b64chars[triple & 0x3F] : '=';
  }

  out[outLen] = '\0';
  return outLen;
}

// -------------------------- END base64 encode --------------------------


// -------------------------- TOUCH & Morse logic --------------------------

// STM32 Blue Pill pins
#define TouchInputPin PA0
#define BuiltInLED    PC13

// Morse detection parameters
const int dotMinDuration      = 200;   // ms (short press -> dot)
const int dashMinDuration     = 400;   // ms (long press -> dash)
const int letterSpaceDuration = 300;   // ms gap to treat as end of sequence

bool         touchActive   = false;
unsigned long touchStart   = 0;
unsigned long lastTouchEnd = 0;
unsigned long timeStamp, timeBudget;

String currentMorse    = "";
String lastPlainWord   = "";
String lastEncBase64   = "";

// AES key and IV (must match Flutter)
const char KEY_STR[17] = "1234567890ABCDEF";  // 16 chars
const char IV_STR[17]  = "FEDCBA0987654321";  // 16 chars

void printHex(const uint8_t *buf, int len) {
  for (int i = 0; i < len; ++i) {
    if (buf[i] < 0x10) Serial.print('0');
    Serial.print(buf[i], HEX);
  }
  Serial.println();
}

// PKCS7 padding
int pkcs7_pad_bytes(const uint8_t *in, int inLen, uint8_t *outBuf, int outBufSize) {
  int pad = 16 - (inLen % 16);
  if (pad == 0) pad = 16;
  int total = inLen + pad;
  if (total > outBufSize) return -1;
  memcpy(outBuf, in, inLen);
  for (int i = inLen; i < total; ++i) outBuf[i] = (uint8_t)pad;
  return total;
}

// Encrypt + Base64 + print + send over Bluetooth (Serial2)
void encryptAndSend(const String &plain) {
  if (plain.length() == 0) return;

  lastPlainWord = plain;   // for OLED display

  Serial.println();
  Serial.println(F("=== AES Encryption ==="));
  Serial.print(F("Plaintext: "));
  Serial.println(plain);

  int plainLen = plain.length();
  uint8_t plainBytes[128];
  if (plainLen > (int)sizeof(plainBytes)) {
    Serial.println(F("Error: plaintext too long"));
    return;
  }
  for (int i = 0; i < plainLen; ++i) plainBytes[i] = (uint8_t)plain[i];

  uint8_t buf[160];
  int paddedLen = pkcs7_pad_bytes(plainBytes, plainLen, buf, sizeof(buf));
  if (paddedLen < 0) {
    Serial.println(F("Error: padding failed"));
    return;
  }

  uint8_t key[16], iv[16];
  memcpy(key, KEY_STR, 16);
  memcpy(iv,  IV_STR,  16);

  AES_CBC_encrypt_buffer(buf, paddedLen, key, iv);

  Serial.print(F("AES Key (ASCII): "));
  Serial.println(KEY_STR);
  Serial.print(F("IV (ASCII): "));
  Serial.println(IV_STR);

  Serial.print(F("Ciphertext (hex): "));
  printHex(buf, paddedLen);

  char b64out[256];
  base64_encode_chars(buf, paddedLen, b64out);
  Serial.print(F("Encrypted (Base64): "));
  Serial.println(b64out);

  lastEncBase64 = String(b64out);  // save for OLED

  Serial.print(F("ENC:"));
  Serial.println(b64out);

  // Send to HC-05 over Serial2 (PA2/PA3)
  Serial2.print(F("ENC:"));
  Serial2.println(b64out);

  Serial.println(F("======================="));
}

// Morse → word mapping
String mapMorseToWord(const String &morse) {
  String s = morse;
  s.replace("_", "-");
  s.trim();
  if (s.length() == 0) return "";

  if (s == "...---..." || s == "-.-" || s == ".") return "SOS";
  if (s == "--" || s == "")                     return "HI";
  if (s == ".-" || s == "._")                   return "HELP";

  return String("[? ") + s + "]";
}

void setup() {
  Serial.begin(115200);   // USB serial
  Serial2.begin(9600);    // HC-05 on PA2 (TX2), PA3 (RX2)

  pinMode(TouchInputPin, INPUT);   // or INPUT_PULLUP / PULLDOWN depending on module
  pinMode(BuiltInLED, OUTPUT);
  digitalWrite(BuiltInLED, HIGH);  // LED off (active LOW)

  timeBudget = 1000000UL / 1000;   // ~1 kHz loop

  u8g2.begin();

  Serial.println(F("=== TOUCH Morse + AES + OLED Started ==="));
  Serial.print(F("Using AES-128-CBC (PKCS7). Key: "));
  Serial.println(KEY_STR);
  Serial.println(F("HC-05 Serial2 started at 9600 baud"));

  Serial2.println("BT_READY");
}

void drawOLED(bool isTouched) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tr);

  // Title
  u8g2.setCursor(0, 10);
  u8g2.print("TOUCH MORSE AES");

  // Touch & LED state
  u8g2.setCursor(0, 25);
  u8g2.print("Touch: ");
  u8g2.print(isTouched ? "ON " : "OFF");

  // Current Morse
  u8g2.setCursor(0, 38);
  u8g2.print("Morse: ");
  // keep line short
  String morseShow = currentMorse;
  if (morseShow.length() > 16) {
    morseShow = morseShow.substring(morseShow.length() - 16);
  }
  u8g2.print(morseShow);

  // Last plain word
  u8g2.setCursor(0, 51);
  u8g2.print("Word: ");
  String wordShow = lastPlainWord;
  if (wordShow.length() > 10) wordShow = wordShow.substring(0, 10);
  u8g2.print(wordShow);

  // Last Base64 (only prefix to fit)
  u8g2.setCursor(0, 63);
  u8g2.print("ENC: ");
  String encShow = lastEncBase64;
  if (encShow.length() > 8) encShow = encShow.substring(0, 8);
  u8g2.print(encShow);

  u8g2.sendBuffer();
}

void loop() {
  timeStamp = micros();

  // 1) Read touch input (HIGH when touched; if opposite, invert here)
  bool isTouched = digitalRead(TouchInputPin);

  // LED feedback: ON when touched
  digitalWrite(BuiltInLED, isTouched ? LOW : HIGH);

  unsigned long now = millis();

  // 2) Detect long inactivity -> treat as end of Morse sequence and encrypt+send
  if (!touchActive && lastTouchEnd > 0 && (now - lastTouchEnd >= letterSpaceDuration)) {
    if (currentMorse.length() > 0) {
      String word = mapMorseToWord(currentMorse);
      if (word.length() > 0) encryptAndSend(word);
      currentMorse = "";
    }
    Serial.print(" ");
    lastTouchEnd = 0;
  }

  // 3) Detect press / release for dot / dash
  if (isTouched) {
    if (!touchActive) {
      touchActive = true;
      touchStart  = now;
    }
  } else {
    if (touchActive) {
      touchActive   = false;
      lastTouchEnd  = now;
      unsigned long pressDuration = now - touchStart;

      if (pressDuration >= dotMinDuration && pressDuration < dashMinDuration) {
        Serial.print(".");
        currentMorse += ".";
      } else if (pressDuration >= dashMinDuration) {
        Serial.print("-");
        currentMorse += "-";
      }
    }
  }

  // 4) Update OLED
  drawOLED(isTouched);

  // 5) Keep ~1 kHz loop rate
  timeStamp = micros() - timeStamp;
  if (timeStamp < timeBudget) delayMicroseconds(timeBudget - timeStamp);
}
