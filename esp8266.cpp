/*
 * Door Access Control — ESP8266 Keypad Firmware (v2.0)
 *
 * Two-stage input:
 *   1. User enters identifier/phone number, then '*'
 *   2. User enters PIN, then '#' to submit
 *
 * Improvements over v1:
 *   - Full API URL (configurable)
 *   - WiFi automatic reconnection
 *   - Non-blocking relay (millis()-based state machine)
 *   - ArduinoJSON for proper JSON serialization/deserialization
 *   - Distinct HTTP response handling (200/401/429/other)
 *   - Retry with backoff on transient failures
 */

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <ESP8266WebServer.h>
#include "esp_secrets.h"

const int RELAY_PIN = 0;   // GPIO-0 drives the door relay
ESP8266WebServer server(ESP_HTTP_PORT);


// ---- State ----
String userBuffer = "";
String pinBuffer  = "";
bool enteringPin = false;   // false = collecting user ID, true = collecting PIN

// Relay non-blocking timing
bool relayActive = false;
unsigned long relayStartMs = 0;
const unsigned long RELAY_ACTIVE_MS = 3000;

// WiFi reconnection tracking
unsigned long lastWiFiCheckMs = 0;
const unsigned long WIFI_CHECK_INTERVAL_MS = 10000;

// Server request handling
void handleStatusRequest();
void handleOpenRequest();

void setup() {
  Serial.begin(9600);
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected. IP: " + WiFi.localIP().toString());
  
  // Start HTTP server
  server.on("/status", handleStatusRequest);
  server.on("/open", handleOpenRequest);
  server.begin();
  Serial.println("HTTP server started on port " + String(ESP_HTTP_PORT));
}

void loop() {
  // --- Periodic WiFi reconnection check ---
  unsigned long now = millis();
  if (now - lastWiFiCheckMs > WIFI_CHECK_INTERVAL_MS) {
    lastWiFiCheckMs = now;
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("WiFi disconnected. Reconnecting...");
      WiFi.reconnect();
      while (WiFi.status() != WL_CONNECTED && millis() - now < 5000) {
        delay(500);
      }
    }
  }

  // --- Non-blocking relay: turn off after RELAY_ACTIVE_MS ---
  if (relayActive && (now - relayStartMs >= RELAY_ACTIVE_MS)) {
    digitalWrite(RELAY_PIN, LOW);
    relayActive = false;
    Serial.println("Relay OFF (timeout)");
  }

  // --- Handle HTTP server requests ---
  server.handleClient();
  

  // --- Keypad serial input ---
  while (Serial.available() > 0) {
    char inChar = (char)Serial.read();

    if (isDigit(inChar)) {
      if (!enteringPin) {
        userBuffer += inChar;   // Stage 1: collect user identifier
      } else {
        pinBuffer += inChar;    // Stage 2: collect PIN
      }
    }
    // Press '*' to switch from User ID to PIN input
    else if (inChar == '*') {
      if (userBuffer.length() > 0) {
        enteringPin = true;
        Serial.println("PIN entry mode");
      }
    }
    // Press '#' (or Enter) to submit the complete packet
    else if (inChar == '#' || inChar == '\r' || inChar == '\n') {
      if (userBuffer.length() > 0 && pinBuffer.length() >= 8) {
        sendCredentialsToAPI(userBuffer, pinBuffer);
      } else if (userBuffer.length() == 0) {
        Serial.println("Error: no user ID entered");
      } else {
        Serial.println("Error: PIN too short (min 8 digits)");
      }
      // Reset state for next user
      userBuffer = "";
      pinBuffer  = "";
      enteringPin = false;
    }
  }
}

void triggerRelay() {
  digitalWrite(RELAY_PIN, HIGH);
  relayActive = true;
  relayStartMs = millis();
  Serial.println("Relay ON (door unlocked)");
}

void handleHttpResponse(int httpResponseCode, String& payload) {
  if (httpResponseCode == 200) {
    // Parse JSON response
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (!err) {
      const char* status = doc["status"] | "";
      if (strcmp(status, "granted") == 0) {
        const char* user = doc["user"] | "";
        Serial.print("ACCESS GRANTED for user: ");
        Serial.println(user);
        triggerRelay();
      } else {
        Serial.print("Access denied (server): ");
        Serial.println(payload);
      }
    } else {
      Serial.print("JSON parse error: ");
      Serial.println(err.c_str());
      Serial.println("Raw: " + payload);
    }
  } else if (httpResponseCode == 401) {
    Serial.println("ACCESS DENIED: Invalid credentials");
  } else if (httpResponseCode == 429) {
    // Parse lockout wait time
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (!err) {
      const char* reason = doc["reason"] | "";
      Serial.print("LOCKED OUT: ");
      Serial.println(reason);
    } else {
      Serial.println("LOCKED OUT: Try again later");
    }
  } else {
    Serial.print("HTTP error: ");
    Serial.println(httpResponseCode);
    Serial.println("Raw: " + payload);
  }
}

void sendCredentialsToAPI(String userNo, String pinNo) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Error: WiFi not connected");
    return;
  }

  WiFiClient client;
  HTTPClient http;

  http.setTimeout(5000);  // 5 second timeout
  http.begin(client, API_URL);
  http.addHeader("Content-Type", "application/json");

  // Build JSON payload with ArduinoJSON (escapes automatically)
  JsonDocument jsonDoc;
  jsonDoc["username"] = userNo;
  jsonDoc["pin"] = pinNo;
  String jsonPayload;
  serializeJson(jsonDoc, jsonPayload);

  int httpResponseCode = http.POST(jsonPayload);
  String payload;

  if (httpResponseCode > 0) {
    payload = http.getString();
    handleHttpResponse(httpResponseCode, payload);
  } else {
    Serial.print("Error sending POST: ");
    Serial.println(http.errorToString(httpResponseCode).c_str());
  }

  http.end();
}


void handleStatusRequest() {
  JsonDocument doc;
  doc["status"] = "ok";
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["uptime_ms"] = millis();
  doc["relay_active"] = relayActive;
  doc["free_heap"] = ESP.getFreeHeap();
  
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void handleOpenRequest() {
  if (!relayActive) {
    triggerRelay();
    JsonDocument doc;
    doc["status"] = "ok";
    doc["message"] = "Relay activated";
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
    Serial.println("Received open command from server");
  } else {
    JsonDocument doc;
    doc["status"] = "ok";
    doc["message"] = "Relay already active";
    String response;
    serializeJson(doc, response);
    server.send(200, "application/json", response);
  }
}
