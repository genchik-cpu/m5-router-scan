// sketch_jul27a.ino — версия для GitHub Actions (Core 3.0.0 с NAPT)

#include <M5StickCPlus2.h>
#include <SPI.h>
#include <Wire.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <esp_system.h>
#include <stdint.h>

extern "C" {
#include "lwip/err.h"
#include "lwip/lwip_napt.h"
}

// Для Core 3.0.0 NAPT реально есть в библиотеке, weak не нужен, но оставим для совместимости
#pragma weak ip_napt_init
#pragma weak ip_napt_enable

extern "C" err_t ip_napt_init(uint16_t max_nat, uint16_t max_port);
extern "C" void ip_napt_enable(uint32_t addr, int enable);

#ifndef WG_CONFIG_DEFINED
#define WG_CONFIG_DEFINED
struct WgConfig {
  String privateKey;
  String address;
  String dns;
  String peerPublicKey;
  String endpointHost;
  uint16_t endpointPort;
  String allowedIPs;
  int persistentKeepalive;
};
#endif

// ---- Функции из wg_manager.ino ----
void wgStorageInit();
void wgManagerBegin();
void wgRegisterWebHandlers();
bool wgIsActive();
IPAddress wgGetLocalIP();
String wgGetDnsServer();
String wgConfiguredName();

const char* AP_SSID = "M5-Setup";
const char* AP_PASS = "m5setup123";

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GW(192, 168, 4, 1);
IPAddress AP_MASK(255, 255, 255, 0);

WebServer server(80);
DNSServer dns;
Preferences prefs;
Preferences safePrefs;

WiFiUDP dnsUdp;
WiFiUDP dnsUp;

const int MAX_LOG = 60;
String logLines[MAX_LOG];
int logCount = 0;

int lastWifiStatus = -1;
unsigned long lastScreen = 0;

bool captiveDns = false;
bool dnsProxy = false;
bool dnsWaiting = false;
unsigned long dnsWaitStart = 0;

IPAddress dnsClientIp;
uint16_t dnsClientPort = 0;
uint8_t dnsBuf[512];

bool naptEnabled = false;
IPAddress currentNaptIp;
bool naptSupported = false;

// ---- Safe-mode флаги ----
bool g_naptOff = false;
bool wgStartAttempted = false;
bool bootMarkedStable = false;
const int MAX_BOOT_FAILS = 3;

void addLog(const String& msg) {
  Serial.println(msg);
  if (logCount < MAX_LOG) {
    logLines[logCount] = msg;
    logCount++;
  } else {
    for (int i = 0; i < MAX_LOG - 1; i++) {
      logLines[i] = logLines[i + 1];
    }
    logLines[MAX_LOG - 1] = msg;
  }
}

static void naptCompatInit() {
  if (g_naptOff) {
    addLog("NAPT init SKIPPED (safe mode)");
    return;
  }
  // В Core 3.0.0 функции реально есть, weak даст их адреса
  naptSupported = (ip_napt_init != nullptr) && (ip_napt_enable != nullptr);
  
  if (!naptSupported) {
    addLog("NAPT NOT AVAILABLE");
    return;
  }

  err_t r = ip_napt_init(64, 32);
  addLog("NAPT init result: " + String((int)r));
}

String resetReasonText() {
  esp_reset_reason_t r = esp_reset_reason();
  switch (r) {
    case ESP_RST_POWERON:   return "Power-on";
    case ESP_RST_EXT:       return "External reset";
    case ESP_RST_SW:        return "Software restart";
    case ESP_RST_PANIC:     return "PANIC / CRASH!";
    case ESP_RST_INT_WDT:   return "Interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "Task watchdog";
    case ESP_RST_WDT:       return "Other watchdog";
    case ESP_RST_DEEPSLEEP: return "Deep sleep wake";
    case ESP_RST_BROWNOUT:  return "Brownout (power!)";
    case ESP_RST_SDIO:      return "SDIO reset";
    default:                return "Unknown (" + String((int)r) + ")";
  }
}

String wifiStatusText(int status) {
  switch (status) {
    case WL_IDLE_STATUS:      return "IDLE";
    case WL_NO_SSID_AVAIL:    return "NO_SSID";
    case WL_SCAN_COMPLETED:   return "SCAN_DONE";
    case WL_CONNECTED:        return "CONNECTED";
    case WL_CONNECT_FAILED:   return "CONNECT_FAIL";
    case WL_CONNECTION_LOST:  return "LOST";
    case WL_DISCONNECTED:     return "DISCONNECTED";
    default:                  return "CODE_" + String(status);
  }
}

String boolText(bool value) {
  return value ? "ON" : "OFF";
}

String pageHead(bool refresh) {
  String h;
  h.reserve(1024);
  h += F("<!DOCTYPE html><html><head>");
  h += F("<meta charset='utf-8'>");
  h += F("<meta name='viewport' content='width=device-width, initial-scale=1'>");
  if (refresh) {
    h += F("<meta http-equiv='refresh' content='5'>");
  }
  h += F("<title>M5 Router</title>");
  h += F("<style>");
  h += F("body{font-family:sans-serif;margin:20px;background:#0b0f14;color:#dfe7ee}");
  h += F(".box{max-width:680px;margin:auto}");
  h += F("a{display:inline-block;margin:8px 0;color:#7fd4ff}");
  h += F("input,textarea{width:100%;padding:10px;margin:8px 0;background:#121a22;color:#fff;border:1px solid #2a3947;border-radius:6px;box-sizing:border-box}");
  h += F("button{width:100%;padding:12px;background:#1f6feb;color:#fff;border:0;border-radius:6px;margin-top:6px}");
  h += F("pre{background:#05080c;color:#7CFC9A;padding:10px;overflow:auto;border-radius:6px;max-height:400px}");
  h += F("h2{margin-top:0}");
  h += F(".cfg{border:1px solid #2a3947;border-radius:6px;padding:8px;margin:6px 0}");
  h += F(".warn{color:#ff6b6b;font-weight:bold}");
  h += F("</style></head><body><div class='box'>");
  return h;
}

String pageFooter() {
  return F("</div></body></html>");
}

void drawScreen() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setTextSize(1);
  M5.Lcd.println("M5 Router");
  M5.Lcd.println("AP: " + String(AP_SSID));
  M5.Lcd.println("Clients: " + String(WiFi.softAPgetStationNum()));

  if (WiFi.status() == WL_CONNECTED) {
    M5.Lcd.println("STA: " + WiFi.SSID());
    M5.Lcd.println("IP: " + WiFi.localIP().toString());
  } else {
    M5.Lcd.println("STA: " + wifiStatusText(WiFi.status()));
  }

  if (!naptSupported) {
    M5.Lcd.println("NAPT: UNSUPPORTED");
  } else {
    M5.Lcd.println("NAPT: " + boolText(naptEnabled) + (g_naptOff ? " [SAFE]" : ""));
  }
  M5.Lcd.println("WG: " + boolText(wgIsActive()) + " " + wgConfiguredName());

  if (dnsProxy) {
    M5.Lcd.println("DNS: PROXY");
  } else if (captiveDns) {
    M5.Lcd.println("DNS: CAPTIVE");
  } else {
    M5.Lcd.println("DNS: OFF");
  }

  M5.Lcd.println("---LOG---");
  int start = 0;
  if (logCount > 5) start = logCount - 5;
  for (int i = start; i < logCount; i++) {
    M5.Lcd.println(logLines[i]);
  }
}

void startCaptiveDns() {
  if (!captiveDns) {
    dns.start(53, "*", AP_IP);
    captiveDns = true;
    addLog("Captive DNS started");
  }
}

void stopCaptiveDns() {
  if (captiveDns) {
    dns.stop();
    captiveDns = false;
    addLog("Captive DNS stopped");
  }
}

void startDnsProxy() {
  if (!dnsProxy) {
    dnsUdp.begin(53);
    dnsUp.begin(1053);
    dnsProxy = true;
    dnsWaiting = false;
