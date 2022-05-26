/*
 * Name:      Wifi DeAuth Detector
 * Purpose:   To detect and record deauthentication attacks
 * By:        Michael Vieau
 * Created:   2022.05.18
 * Modified:  2022.05.25
 * Rev Level  1.1
 */

// References:
// https://github.com/spacehuhn/DeauthDetector
// ESP8266 enhanced sniffer by Kosme https://github.com/kosme

// include necessary libraries
#include <ESP8266WiFi.h>
#include <Adafruit_NeoPixel.h>
#include <SD.h>
#include <SPI.h>
#include "./structures.h"

#ifdef __AVR__
 #include <avr/power.h> // Required for 16 MHz Adafruit Trinket
#endif

// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

// ===== SETTINGS ===== //
#define LEDPIN 4           /* On Trinket or Gemma, suggest changing this to 1 */
#define NUMPIXELS 3        /* Total number of NeoPixels used*/
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 2         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */
#define DELAYVAL 500       /* Time (in milliseconds) to pause between pixels */

// Variables
const int chipSelect = D4;
const short channels[] = { 1,2,3,4,5,6,7,8,9,10,11,/*12,13,14*/ };
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
String dataString = "";           // Variable used to write data to a file
String FilePrefix = "Wifi-Attacks-";
int FileNum = 0;
String OutputFile = "temp.txt";

Adafruit_NeoPixel pixels(NUMPIXELS, LEDPIN, NEO_GRB + NEO_KHZ800);

// ================================================================
void setup() {
  Serial.begin(SERIAL_BAUD);            // Start serial communication

  pixels.begin();
  pixels.setBrightness(25);
  pixels.clear();
  
  WiFi.disconnect();                    // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);        // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer);  // Set sniffer function
  wifi_set_channel(channels[0]);        // Set channel
  wifi_promiscuous_enable(true);        // Enable sniffer

  // see if the card is present and can be initialized:
  Serial.print("Initializing SD card...");
  if (!SD.begin(chipSelect)) {
    Serial.println("Card failed, or not present");
    pixels.setPixelColor(0, pixels.Color(255, 0, 0));
    pixels.show();
    // don't do anything more:
    return;
  }
  Serial.println("card initialized.");
  Serial.println("Creating file...");
  filecreate();
  
  pixels.setPixelColor(0, pixels.Color(0, 255, 0));
  pixels.show();
}
// ================================================================
void filecreate()
{
  if (SD.exists(FilePrefix + FileNum + ".txt")) {
    FileNum++;
    filecreate();
  }
  else {
    OutputFile = (FilePrefix + FileNum + ".txt");
    Serial.print("Created file: ");
    Serial.println(OutputFile);

    File dataFile = SD.open(OutputFile, FILE_WRITE);
    if (dataFile) {
      dataFile.println("Starting to look for wireless attacks...");
      dataFile.close();
    }
  }
}
// ================================================================
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)
  
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels)*CH_TIME)) {
    update_time = current_time; // Update time variable

    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter; // Increment attack counter
    } else {
      if(attack_counter >= PKT_TIME) attack_stopped();
      attack_counter = 0; // Reset attack counter
    }

    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
    }

    Serial.print("Packets/s: ");
    Serial.println(packet_rate);
    
    packet_rate = 0; // Reset packet rate
  }

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable

    // Get next channel
    ch_index = (ch_index+1) % (sizeof(channels)/sizeof(channels[0]));
    short ch = channels[ch_index];

    // Set channel
    wifi_set_channel(ch);
  }
}
// ================================================================
void sniffer(uint8_t *buf, uint16_t len) {
  
  if (!buf || len < 28) return; // Drop packets without MAC header

  byte pkt_type = buf[12]; // second half of frame control field
  //byte* addr_a = &buf[16]; // first MAC address
  //byte* addr_b = &buf[22]; // second MAC address

  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate;
    File dataFile = SD.open(OutputFile, FILE_WRITE);
    for(int i=0;i<5;i++) {
      Serial.printf("%02x:",buf[22+i]);
      if (dataFile) {
        dataFile.printf("%02x:",buf[22+i]);
      }
    }
    Serial.printf("%02x  ",buf[22+5]);
      if (dataFile) {
        dataFile.printf("%02x",buf[22+5]);
    }
    // Signal strength is in byte 0
    Serial.printf("%i\n",int8_t(buf[0]));
    if (dataFile) {
        dataFile.print(",");
        dataFile.printf("%i\n",int8_t(buf[0]));
        dataFile.close();
    }
  }
}
// ================================================================
void attack_started() {
  pixels.setPixelColor(1, pixels.Color(255, 0, 0));
  pixels.setPixelColor(2, pixels.Color(255, 0, 0));
  pixels.show();
  Serial.println("ATTACK DETECTED");
  write_to_file("****** Attack Detected ******");
}
// ================================================================
void attack_stopped() {
  pixels.setPixelColor(2, pixels.Color(0, 0, 0));
  pixels.show();
  Serial.println("ATTACK STOPPED");
}
// ================================================================
void write_to_file( String dataString ) {
  // open the file. note that only one file can be open at a time,
  // so you have to close this one before opening another.
  File dataFile = SD.open(OutputFile, FILE_WRITE);

  // if the file is available, write to it:
  if (dataFile) {
    dataFile.println(dataString);
    dataFile.close();
  }
  else {
    Serial.println("error opening " + OutputFile);
  }
}
// ================================================================
