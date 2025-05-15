#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>

DWORD GetProcessIdByName(const std::string& processName);
uintptr_t ScanPattern(HANDLE hProcess, const std::vector<BYTE>& pattern, const std::vector<bool>& mask);
std::vector<std::pair<std::vector<BYTE>, std::vector<bool>>> ParseAOBPattern(const std::string& pattern);
float ReadFloat(HANDLE hProcess, uintptr_t address);
bool WriteFloat(HANDLE hProcess, uintptr_t address, float value);

uintptr_t ScanPattern(HANDLE hProcess, const std::vector<BYTE>& pattern, const std::vector<bool>& mask) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t minAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION memInfo;
    std::atomic<uintptr_t> result(0);
    std::vector<std::thread> threads;

	// divide regions into chunks and scan in parallel for fastest results
    while (minAddress < maxAddress) {
        if (VirtualQueryEx(hProcess, (LPCVOID)minAddress, &memInfo, sizeof(memInfo))) {
            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Protect & PAGE_READWRITE ||
                 memInfo.Protect & PAGE_EXECUTE_READWRITE ||
                 memInfo.Protect & PAGE_READONLY ||
                 memInfo.Protect & PAGE_EXECUTE_READ) &&
                !(memInfo.Protect & PAGE_GUARD)) {

				// start thread to scan region
                threads.emplace_back([hProcess, memInfo, &pattern, &mask, &result]() {
                    if (result.load(std::memory_order_relaxed) != 0) return; // exit if we already found valid address

                    std::vector<BYTE> buffer(memInfo.RegionSize);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                        for (SIZE_T i = 0; i < bytesRead - pattern.size(); i++) {
                            bool found = true;

                            for (size_t j = 0; j < pattern.size(); j++) {
                                if (mask[j] && buffer[i + j] != pattern[j]) {
                                    found = false;
                                    break;
                                }
                            }

                            if (found) {
                                result.store((uintptr_t)memInfo.BaseAddress + i, std::memory_order_relaxed);
                                return;
                            }
                        }
                    }
                });
            }

            minAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
        } else {
            minAddress += 4096; // skip invalid regions
        }
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return result.load(std::memory_order_relaxed);
}

int main() {
    std::cout << "Torchlight Infinite Zoom" << std::endl;
    std::cout << "------------------------" << std::endl;

    DWORD processId = GetProcessIdByName("torchlight_infinite.exe");
    if (processId == 0) {
        std::cout << "Could not find torchlight_infinite.exe. Is the game running?" << std::endl;
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "Found Torchlight Infinite (PID: " << processId << ")" << std::endl;

    // Open process with required access rights
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "== RUN AS ADMIN! == " << std::endl;
        std::cout << "Error: Could not open process. Error code: " << GetLastError() << std::endl;
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

	// AOB pattern for camera zoom value
    std::string aobPattern = "00 ?? ?? 45 FE FF 33 C2 00 00 00 00 00 00 00 00 00 80 3B 45";
    auto parsedPatterns = ParseAOBPattern(aobPattern);

    if (parsedPatterns.empty()) {
        std::cout << "Error: Invalid AOB pattern" << std::endl;
        CloseHandle(hProcess);
        std::cout << "Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    // Get the first pattern
    auto pattern = parsedPatterns[0].first;
    auto mask = parsedPatterns[0].second;

    float targetZoom = 0.0f;
    uintptr_t currentAddress = 0;

    // Prompt user to set the initial zoom value
    std::cout << "Enter initial zoom value: ";
    std::string input;
    std::getline(std::cin, input);

    try {
        targetZoom = std::stof(input);
        std::cout << "Zoom value set to: " << targetZoom << std::endl;
    }
    catch (const std::exception&) {
        std::cout << "Invalid input. Please enter a valid number." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Main loop
    while (true) {
        // Continuously scan for the updated address
        uintptr_t newAddress = ScanPattern(hProcess, pattern, mask);

        if (newAddress != 0 && newAddress != currentAddress) {
            currentAddress = newAddress;
            std::cout << "Found updated zoom address at: 0x" << std::hex << std::uppercase
                << currentAddress << std::dec << std::endl;

            // Apply the target zoom value to the new address
            if (WriteFloat(hProcess, currentAddress, targetZoom)) {
                std::cout << "Applied zoom value " << targetZoom
                    << " to updated address" << std::endl;
            }
            else {
                std::cout << "Error: Failed to write zoom value to updated address!" << std::endl;
            }
        }

        //reduces cpu but makes it slower not needed now
        //std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Clean up
    CloseHandle(hProcess);
    return 0;
}

DWORD GetProcessIdByName(const std::string& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                // WCHAR to std::string conversion that shouldn'ttttttt break
                char exeFileAnsi[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, processEntry.szExeFile, -1, exeFileAnsi, MAX_PATH, NULL, NULL);
                std::string currentProcessName = exeFileAnsi;

                if (_stricmp(currentProcessName.c_str(), processName.c_str()) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return processId;
}

// Parser for AOB
std::vector<std::pair<std::vector<BYTE>, std::vector<bool>>> ParseAOBPattern(const std::string& pattern) {
    std::vector<std::pair<std::vector<BYTE>, std::vector<bool>>> result;
    std::vector<BYTE> bytes;
    std::vector<bool> mask;

    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token) {
        if (token == "??") {
            bytes.push_back(0);
            mask.push_back(false);
        }
        else {
            try {
                BYTE byte = (BYTE)std::stoi(token, nullptr, 16);
                bytes.push_back(byte);
                mask.push_back(true);
            }
            catch (const std::exception&) {
                std::cout << "Warning: Invalid byte in pattern: " << token << std::endl;
                continue;
            }
        }
    }

    if (!bytes.empty()) {
        result.push_back(std::make_pair(bytes, mask));
    }

    return result;
}

float ReadFloat(HANDLE hProcess, uintptr_t address) {
    float value = 0.0f;
    SIZE_T bytesRead;

    ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(float), &bytesRead);

    return (bytesRead == sizeof(float)) ? value : 0.0f;
}

bool WriteFloat(HANDLE hProcess, uintptr_t address, float value) {
    SIZE_T bytesWritten;

    return WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(float), &bytesWritten) &&
        (bytesWritten == sizeof(float));
}