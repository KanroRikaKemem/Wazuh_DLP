``` cpp
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdio> 
#include <unordered_map> 
#include <shlobj.h>
#include <cctype>

struct BlacklistEntry {
    std::string originalPath;
    std::string fullName;
    std::string baseName;
    std::string extension;
};

// --- GLOBAL VARIABLES ---
HHOOK hKeyboardHook;
HHOOK hMouseHook;
bool isSensitiveDataOnScreen = false;
std::string currentSensitiveWindowTitle = "";
std::string currentMatchedPath = "";
std::string currentProcessName = "";

// BỘ NHỚ ĐỆM CACHE WMI
std::unordered_map<DWORD, std::string> pidPathCache;

const std::string LOG_FILE = "C:\\Users\\Public\\yara_debug.log";
const std::string BLACKLIST_FILE = "C:\\Users\\Public\\blacklist.txt";

std::vector<BlacklistEntry> sensitiveEntries;
const std::wstring BLACKLIST_PROCESSES[] = { L"SnippingTool.exe", L"ScreenClippingHost.exe" };

int blockedScreenshotCount = 0;
std::chrono::time_point<std::chrono::system_clock> firstBlockTime;
bool isShieldTemporarilyDisabled = false;
std::chrono::time_point<std::chrono::system_clock> disableStartTime;
const int MAX_BLOCKS_ALLOWED = 5;
const int BLOCK_TIME_WINDOW_SECONDS = 20;
const int DISABLE_DURATION_SECONDS = 60;

const std::string YARA_EXE = "\"C:\\Program Files (x86)\\ossec-agent\\dependencies\\yara\\yara64.exe\"";
const std::string YARA_RULE = "\"C:\\Program Files (x86)\\ossec-agent\\shared\\sensitive_data.yar\"";
const std::string TEMP_CLIP_FILE = "C:\\Users\\Public\\wazuh_clip_temp.txt";

bool isClipboardToxic = false;
std::string toxicSourceApp = "";
std::string toxicSourceTitle = "";

const std::string TRUSTED_APPS[] = { "winword.exe", "excel.exe", "notepad.exe", "explorer.exe", "screenguard.exe", "cmd.exe", "powershell.exe" };

HWND hHiddenWindow = NULL;

int toxicCopyCount = 0;
std::chrono::time_point<std::chrono::system_clock> firstToxicCopyTime;
bool isClipboardOverrideActive = false;
std::chrono::time_point<std::chrono::system_clock> clipboardOverrideStartTime;
const int MAX_COPY_ALLOWED = 10;
const int COPY_TIME_WINDOW_SECONDS = 30;
const int CLIPBOARD_DISABLE_DURATION_SECONDS = 60;

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::string toLowerCase(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

bool ContainsWholeWord(const std::string& text, const std::string& word) {
    size_t pos = text.find(word);
    while (pos != std::string::npos) {
        bool startBoundary = (pos == 0) || !isalnum(text[pos - 1]);
        bool endBoundary = (pos + word.length() == text.length()) || !isalnum(text[pos + word.length()]);

        if (startBoundary && endBoundary) {
            return true;
        }
        pos = text.find(word, pos + 1);
    }
    return false;
}

std::string GetCurrentTimestamp() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void WriteToLog(const std::string& message) {
    std::ofstream logFile(LOG_FILE, std::ios_base::app);
    if (logFile.is_open()) {
        logFile << GetCurrentTimestamp() << " " << message << "\n";
        logFile.close();
    }
}

// HÀM WMI LẤY ĐƯỜNG DẪN TỪ PID
std::string GetFilePathFromPID(DWORD pid) {
    std::string cmd = "wmic process where processid=" + std::to_string(pid) + " get commandline";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";

    char buffer[512];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    _pclose(pipe);

    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());

    size_t exePos = toLowerCase(result).find(".exe");
    if (exePos != std::string::npos) {
        std::string args = result.substr(exePos + 4);

        size_t drivePos = args.find(":\\");
        if (drivePos != std::string::npos && drivePos >= 1) {
            size_t startPos = drivePos - 1;
            std::string realPath = args.substr(startPos);

            if (args[startPos - 1] == '"') {
                size_t endQuote = realPath.find('"');
                if (endQuote != std::string::npos) {
                    realPath = realPath.substr(0, endQuote);
                }
            }
            else {
                size_t nextSpace = realPath.find(' ');
                if (nextSpace != std::string::npos) {
                    realPath = realPath.substr(0, nextSpace);
                }
            }

            while (!realPath.empty() && isspace(realPath.back())) {
                realPath.pop_back();
            }
            return realPath;
        }
    }
    return "";
}

void VerifyBlacklistIntegrity() {
    std::vector<std::string> survivingPaths;
    bool listChanged = false;

    std::ifstream file(BLACKLIST_FILE);
    std::vector<std::string> currentPaths;
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            line.erase(0, line.find_first_not_of(" \n\r\t"));
            if (!line.empty()) currentPaths.push_back(line);
        }
        file.close();
    }

    for (const std::string& path : currentPaths) {
        if (path.find(":\\") != std::string::npos) {
            WIN32_FILE_ATTRIBUTE_DATA fileInfo;
            if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fileInfo)) {
                survivingPaths.push_back(path);
            }
            else {
                listChanged = true;
                std::cout << "[SELF-HEAL] File deleted from disk. Removing from Blacklist: " << path << "\n";
                WriteToLog("INFO: Data Lineage: File physically deleted. Removed from Blacklist [" + path + "]");
            }
        }
        else {
            survivingPaths.push_back(path);
        }
    }

    if (listChanged) {
        std::ofstream outFile(BLACKLIST_FILE, std::ios::trunc);
        if (outFile.is_open()) {
            for (const std::string& p : survivingPaths) {
                outFile << p << "\n";
            }
            outFile.close();
        }
    }
}

std::string GetProcessNameFromHwnd(HWND hwnd) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return "UnknownApp";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        char path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            std::string fullPath(path);
            size_t pos = fullPath.find_last_of("\\/");
            return toLowerCase((pos == std::string::npos) ? fullPath : fullPath.substr(pos + 1));
        }
        CloseHandle(hProcess);
    }
    return "unknownapp.exe";
}

std::string CleanWindowTitle(std::string title) {
    size_t pos = title.find(" and ");
    if (pos != std::string::npos) {
        title = title.substr(0, pos);
    }

    std::vector<std::string> garbageSuffixes = {
        " - Microsoft", " - Google Chrome", " - Mozilla Firefox", " - Cốc Cốc",
        " - Profile 1", " - Personal", " - Notepad", " - Word"
    };

    for (const std::string& suffix : garbageSuffixes) {
        pos = title.find(suffix);
        if (pos != std::string::npos) {
            title = title.substr(0, pos);
        }
    }

    while (!title.empty() && isspace(title.back())) {
        title.pop_back();
    }
    return title;
}

void LoadBlacklist() {
    sensitiveEntries.clear();
    std::ifstream file(BLACKLIST_FILE);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            line.erase(0, line.find_first_not_of(" \n\r\t"));

            if (!line.empty()) {
                BlacklistEntry entry;
                entry.originalPath = line;

                std::string filename = line;
                size_t pos = filename.find_last_of("\\/");
                if (pos != std::string::npos) {
                    filename = filename.substr(pos + 1);
                }
                entry.fullName = toLowerCase(filename);

                size_t dotPos = entry.fullName.find_last_of(".");
                if (dotPos != std::string::npos) {
                    entry.baseName = entry.fullName.substr(0, dotPos);
                    entry.extension = entry.fullName.substr(dotPos);
                }
                else {
                    entry.baseName = entry.fullName;
                    entry.extension = "";
                }

                if (!entry.fullName.empty()) {
                    sensitiveEntries.push_back(entry);
                }
            }
        }
        file.close();
    }
}

DWORD WINAPI ShowWarningMsg(LPVOID lpParam) {
    MessageBoxA(NULL,
        "Screenshot attempt blocked!\nSensitive data is currently displayed on your screen.\n\nThis security event has been logged and reported.",
        "Wazuh DLP - Security Alert",
        MB_ICONWARNING | MB_OK | MB_TOPMOST);
    return 0;
}

DWORD WINAPI ShowBreakGlassMsg(LPVOID lpParam) {
    MessageBoxA(NULL,
        "Emergency Override Activated!\n\nScreenshot protection is temporarily disabled for 60 seconds. You may now capture the screen.\n\nNote: This override event has been logged and reported to the administrator.",
        "Wazuh DLP - Emergency Override",
        MB_ICONINFORMATION | MB_OK | MB_TOPMOST);
    return 0;
}

DWORD WINAPI ShowClipboardWarningMsg(LPVOID lpParam) {
    MessageBoxA(NULL,
        "Clipboard Blocked!\n\nYou attempted to paste/drop sensitive data into an UNTRUSTED application. The action has been blocked.",
        "Wazuh DLP - Zero Trust Protection",
        MB_ICONERROR | MB_OK | MB_TOPMOST);
    return 0;
}

std::string ReadClipboardText() {
    for (int i = 0; i < 3; ++i) {
        if (OpenClipboard(nullptr)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pszText = static_cast<wchar_t*>(GlobalLock(hData));
                std::string text = "";
                if (pszText) {
                    text = WStringToString(pszText);
                    GlobalUnlock(hData);
                }
                CloseClipboard();
                return text;
            }
            CloseClipboard();
        }
        Sleep(20);
    }
    return "";
}

bool CheckClipboardForToxicFiles() {
    bool foundToxicFile = false;
    for (int i = 0; i < 3; ++i) {
        if (OpenClipboard(nullptr)) {
            HANDLE hData = GetClipboardData(CF_HDROP);
            if (hData) {
                HDROP hDrop = static_cast<HDROP>(GlobalLock(hData));
                if (hDrop) {
                    UINT fileCount = DragQueryFileA(hDrop, 0xFFFFFFFF, NULL, 0);
                    char filePath[MAX_PATH];

                    for (UINT j = 0; j < fileCount; ++j) {
                        if (DragQueryFileA(hDrop, j, filePath, MAX_PATH)) {
                            std::string pathStr = std::string(filePath);
                            std::string pathLower = toLowerCase(pathStr);

                            for (const auto& entry : sensitiveEntries) {
                                std::string entryLower = toLowerCase(entry.originalPath);
                                if (pathLower == entryLower) {
                                    std::cout << "[DLP] SENSITIVE FILE COPIED TO CLIPBOARD: " << pathStr << "\n";
                                    toxicSourceApp = "Windows Explorer (File Copy)";
                                    toxicSourceTitle = pathStr;
                                    foundToxicFile = true;
                                    break;
                                }
                            }
                        }
                        if (foundToxicFile) break;
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
            if (foundToxicFile) return true;
        }
        Sleep(20);
    }
    return false;
}

bool RunYaraOnText(const std::string& text) {
    std::ofstream out(TEMP_CLIP_FILE, std::ios::binary);
    out << text;
    out.close();

    Sleep(150);

    std::string cmd = "\"" + YARA_EXE + " -w " + YARA_RULE + " \"" + TEMP_CLIP_FILE + "\" 2>&1\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;

    char buffer[128];
    std::string result = "";
    while (fgets(buffer, 128, pipe) != NULL) {
        result += buffer;
    }
    _pclose(pipe);

    DeleteFileA(TEMP_CLIP_FILE.c_str());

    std::cout << ">> [YARA RAW OUTPUT]:\n" << (result.empty() ? "No output" : result) << "\n";
    return result.find("Detect_Sensitive_Info") != std::string::npos;
}

void ClearClipboard(const std::string& targetApp, const std::string& targetTitle) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
        std::cout << "[DLP] TOXIC CLIPBOARD CLEARED! Prevented paste to untrusted app: " << targetApp << "\n";
        std::cout << "      -> Destination Title: " << targetTitle << "\n";

        std::string logMsg = "wazuh-dlp: alert - Clipboard Blocked | Source: [" + toxicSourceApp + " - " + toxicSourceTitle + "] | Destination: [" + targetApp + " - " + targetTitle + "] | Rule: [YARA_Sensitive_Data]";
        WriteToLog(logMsg);

        CreateThread(NULL, 0, ShowClipboardWarningMsg, NULL, 0, NULL);
    }
}

LRESULT CALLBACK HiddenWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_CLIPBOARDUPDATE) {
        if (isClipboardOverrideActive) return DefWindowProc(hwnd, uMsg, wParam, lParam);

        if (CheckClipboardForToxicFiles()) {
            isClipboardToxic = true;
            std::cout << "[DLP] ASYNC SCAN: Toxic FILE detected in clipboard. Flag SET.\n";
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }

        std::string copiedText = ReadClipboardText();
        if (!copiedText.empty()) {

            auto currentTime = std::chrono::system_clock::now();
            if (toxicCopyCount == 0) {
                firstToxicCopyTime = currentTime;
            }

            auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentTime - firstToxicCopyTime).count();

            if (elapsedSeconds <= COPY_TIME_WINDOW_SECONDS) {
                toxicCopyCount++;
                if (toxicCopyCount >= MAX_COPY_ALLOWED) {
                    isClipboardOverrideActive = true;
                    clipboardOverrideStartTime = currentTime;
                    toxicCopyCount = 0;
                    std::cout << "[SECRET] Clipboard Override Activated!\n";
                    WriteToLog("wazuh-dlp: alert - Secret clipboard override activated. Paste allowed to any app.");
                    return DefWindowProc(hwnd, uMsg, wParam, lParam);
                }
            }
            else {
                toxicCopyCount = 1;
                firstToxicCopyTime = currentTime;
            }

            isClipboardToxic = false;
            std::cout << "[DLP] Scanning clipboard text with YARA...\n";
            if (RunYaraOnText(copiedText)) {
                isClipboardToxic = true;

                HWND hwndSource = GetForegroundWindow();
                toxicSourceApp = GetProcessNameFromHwnd(hwndSource);

                char title[512];
                GetWindowTextA(hwndSource, title, sizeof(title));

                toxicSourceTitle = CleanWindowTitle(std::string(title));
                if (toxicSourceTitle.empty()) toxicSourceTitle = "Unknown Window";

                std::cout << "[DLP] ASYNC SCAN: YARA detected toxic data. Flag SET.\n";
                std::cout << "      -> Source App: " << toxicSourceApp << "\n";
                std::cout << "      -> Source Title: " << toxicSourceTitle << "\n";
            }
            else {
                std::cout << "[DLP] ASYNC SCAN: Data is clean.\n";
            }
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKeyBoard = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {

            if (pKeyBoard->vkCode == VK_SNAPSHOT) {
                if (isSensitiveDataOnScreen && !isShieldTemporarilyDisabled) {

                    auto currentTime = std::chrono::system_clock::now();
                    if (blockedScreenshotCount == 0) firstBlockTime = currentTime;

                    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentTime - firstBlockTime).count();

                    if (elapsedSeconds <= BLOCK_TIME_WINDOW_SECONDS) {
                        blockedScreenshotCount++;

                        if (blockedScreenshotCount >= MAX_BLOCKS_ALLOWED) {
                            isShieldTemporarilyDisabled = true;
                            disableStartTime = currentTime;
                            blockedScreenshotCount = 0;

                            std::cout << "[EMERGENCY] OVERRIDE ACTIVATED! SHIELD DOWN.\n";
                            WriteToLog("wazuh-dlp: alert - Emergency override activated. Target Path: [" + currentMatchedPath + "] | App: [" + currentProcessName + "]");
                            CreateThread(NULL, 0, ShowBreakGlassMsg, NULL, 0, NULL);
                            return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
                        }
                    }
                    else {
                        blockedScreenshotCount = 1;
                        firstBlockTime = currentTime;
                    }

                    std::cout << "[BLOCKED] Screenshot attempt detected! Action swallowed.\n";
                    WriteToLog("wazuh-dlp: alert - Screenshot blocked. Source Path: [" + currentMatchedPath + "] | App: [" + currentProcessName + "]");
                    CreateThread(NULL, 0, ShowWarningMsg, NULL, 0, NULL);
                    return 1;
                }
            }

            bool isCtrlV = (pKeyBoard->vkCode == 0x56 && (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0);
            bool isShiftInsert = (pKeyBoard->vkCode == VK_INSERT && (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0);

            if (isCtrlV || isShiftInsert) {
                if (isClipboardToxic && !isClipboardOverrideActive) {
                    HWND hwnd = GetForegroundWindow();
                    std::string procName = GetProcessNameFromHwnd(hwnd);

                    if (procName != "unknownapp.exe" && procName != "") {
                        bool isTrusted = false;
                        for (const std::string& app : TRUSTED_APPS) {
                            if (procName == app) { isTrusted = true; break; }
                        }

                        char title[512];
                        GetWindowTextA(hwnd, title, sizeof(title));
                        std::string windowTitle = CleanWindowTitle(std::string(title));
                        if (windowTitle.empty()) windowTitle = "Unknown Tab";

                        if (!isTrusted) {
                            ClearClipboard(procName, windowTitle);
                            isClipboardToxic = false;
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_RBUTTONDOWN || wParam == WM_RBUTTONUP) {
            if (isClipboardToxic && !isClipboardOverrideActive) {
                HWND hwnd = GetForegroundWindow();
                std::string procName = GetProcessNameFromHwnd(hwnd);

                if (procName != "unknownapp.exe" && procName != "") {
                    bool isTrusted = false;
                    for (const std::string& app : TRUSTED_APPS) {
                        if (procName == app) { isTrusted = true; break; }
                    }

                    char title[512];
                    GetWindowTextA(hwnd, title, sizeof(title));
                    std::string windowTitle = CleanWindowTitle(std::string(title));
                    if (windowTitle.empty()) windowTitle = "Unknown Tab";

                    if (!isTrusted) {
                        ClearClipboard(procName, windowTitle);
                        isClipboardToxic = false;
                    }
                }
            }
        }
    }
    return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

void KillProcessByName(const std::wstring& processName) {
    if (isShieldTemporarilyDisabled) return;

    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pEntry;
    pEntry.dwSize = sizeof(PROCESSENTRY32W);
    BOOL hRes = Process32FirstW(hSnapShot, &pEntry);

    while (hRes) {
        if (processName == pEntry.szExeFile) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pEntry.th32ProcessID);
            if (hProcess != NULL) {
                TerminateProcess(hProcess, 9);
                CloseHandle(hProcess);
                std::string procNameStr = WStringToString(processName);

                std::cout << "[BLOCKED] Snipping tool killed: " << procNameStr << "\n";
                WriteToLog("wazuh-dlp: alert - Screen clipping tool (" + procNameStr + ") killed. Protecting Source Path: [" + currentMatchedPath + "]");
            }
        }
        hRes = Process32NextW(hSnapShot, &pEntry);
    }
    CloseHandle(hSnapShot);
}

// --- LUỒNG QUÉT (ĐỐI CHIẾU ĐƯỜNG DẪN TRỰC TIẾP WMI VS BLACKLIST) ---
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    bool* foundSensitive = (bool*)lParam;

    if (IsWindowVisible(hwnd) && !IsIconic(hwnd)) {

        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        if (windowPid == GetCurrentProcessId()) {
            return TRUE;
        }

        std::string procName = GetProcessNameFromHwnd(hwnd);

        if (procName == "explorer.exe" || procName == "cmd.exe" || procName == "conhost.exe") {
            return TRUE;
        }

        char windowTitle[512];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        std::string titleStr = toLowerCase(std::string(windowTitle));

        if (!titleStr.empty()) {
            for (const BlacklistEntry& entry : sensitiveEntries) {
                bool isMatch = false;

                if (ContainsWholeWord(titleStr, entry.fullName)) {
                    isMatch = true;
                }
                else if (ContainsWholeWord(titleStr, entry.baseName)) {
                    if (entry.extension == ".txt" || entry.extension == ".log" || entry.extension == ".csv") {
                        if (procName == "notepad.exe" || procName == "wordpad.exe" || procName == "excel.exe") isMatch = true;
                    }
                    else if (entry.extension == ".docx" || entry.extension == ".doc") {
                        if (procName == "winword.exe" || procName == "wordpad.exe") isMatch = true;
                    }
                    else if (entry.extension == ".xlsx" || entry.extension == ".xls") {
                        if (procName == "excel.exe") isMatch = true;
                    }
                    else if (entry.extension == ".pdf") {
                        if (procName == "acrord32.exe" || procName == "msedge.exe" || procName == "chrome.exe" || procName == "foxitpdfreader.exe") isMatch = true;
                    }
                    else if (entry.extension == ".pptx" || entry.extension == ".ppt") {
                        if (procName == "powerpnt.exe") isMatch = true;
                    }
                    else if (entry.extension.empty()) {
                        isMatch = true;
                    }
                }

                // --- KIỂM TRA CHÉO CHÍNH XÁC 100% ---
                if (isMatch) {
                    std::string realPath = "";
                    bool isNewlyCached = false;

                    if (pidPathCache.find(windowPid) != pidPathCache.end()) {
                        realPath = pidPathCache[windowPid];
                    }
                    else {
                        realPath = GetFilePathFromPID(windowPid);
                        if (!realPath.empty()) {
                            pidPathCache[windowPid] = realPath;
                            isNewlyCached = true;
                        }
                    }

                    if (!realPath.empty()) {
                        std::string lowerRealPath = toLowerCase(realPath);
                        std::string lowerBlacklistPath = toLowerCase(entry.originalPath);

                        if (isNewlyCached) {
                            std::cout << "[DEBUG] WMI moi duoc duong dan -> Path: " << realPath << "\n";
                        }

                        // KHÔNG CẦN ADS NỮA. CHỈ CẦN SO SÁNH ĐƯỜNG DẪN!
                        if (lowerRealPath != lowerBlacklistPath) {
                            if (isNewlyCached) {
                                std::cout << "[SAFE] File trung ten (" << entry.baseName << ") nhung khac thu muc. Bo qua!\n";
                            }
                            isMatch = false;
                        }
                        else {
                            if (isNewlyCached) {
                                std::cout << "[DANGER] Chinh xac la file cam (" << entry.baseName << ")! Chuan bi bat khien.\n";
                            }
                        }
                    }
                }
                // --- KẾT THÚC KIỂM TRA CHÉO ---

                if (isMatch) {
                    *foundSensitive = true;
                    currentSensitiveWindowTitle = std::string(windowTitle);
                    currentMatchedPath = entry.originalPath;
                    currentProcessName = procName;
                    return FALSE;
                }
            }
        }
    }
    return TRUE;
}

DWORD WINAPI WatchdogThread(LPVOID lpParam) {
    bool previousState = false;
    int reloadCounter = 0;
    int integrityCounter = 0;

    while (true) {
        if (reloadCounter >= 10) {
            LoadBlacklist();
            reloadCounter = 0;
        }
        reloadCounter++;

        if (integrityCounter >= 120) {
            VerifyBlacklistIntegrity();
            LoadBlacklist();
            pidPathCache.clear();
            integrityCounter = 0;
        }
        integrityCounter++;

        if (isShieldTemporarilyDisabled) {
            auto currentTime = std::chrono::system_clock::now();
            auto elapsedDisableTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - disableStartTime).count();
            if (elapsedDisableTime >= DISABLE_DURATION_SECONDS) {
                isShieldTemporarilyDisabled = false;
                std::cout << "[INFO] Emergency override expired. Shield RE-ENABLED.\n";
                WriteToLog("INFO: Emergency override expired. Screenshot protection re-enabled.");
            }
        }

        if (isClipboardOverrideActive) {
            auto currentTime = std::chrono::system_clock::now();
            auto elapsedDisableTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - clipboardOverrideStartTime).count();
            if (elapsedDisableTime >= CLIPBOARD_DISABLE_DURATION_SECONDS) {
                isClipboardOverrideActive = false;
                std::cout << "[INFO] Secret Clipboard Override expired.\n";
                WriteToLog("INFO: Secret Clipboard Override expired. Protection re-enabled.");
            }
        }

        bool currentFoundSensitive = false;
        if (sensitiveEntries.size() > 0) {
            EnumWindows(EnumWindowsProc, (LPARAM)&currentFoundSensitive);
        }

        isSensitiveDataOnScreen = currentFoundSensitive;

        if (isSensitiveDataOnScreen && !previousState) {
            std::cout << "\n[ALERT] SENSITIVE CONTENT DETECTED ON SCREEN!\n";
            std::cout << ">> File: " << currentMatchedPath << "\n";
            std::cout << ">> App:  " << currentProcessName << "\n";
            std::cout << ">> ANTI-SCREENSHOT SHIELD ACTIVATED!\n";
            previousState = true;
        }
        else if (!isSensitiveDataOnScreen && previousState) {
            std::cout << "\n[INFO] Screen is clear. Shield deactivated.\n";
            currentSensitiveWindowTitle = "";
            currentMatchedPath = "";
            currentProcessName = "";
            previousState = false;
            blockedScreenshotCount = 0;
            isShieldTemporarilyDisabled = false;
        }

        if (isSensitiveDataOnScreen && !isShieldTemporarilyDisabled) {
            for (const std::wstring& proc : BLACKLIST_PROCESSES) {
                KillProcessByName(proc);
            }
        }

        Sleep(500);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-hide") {
            HWND hWnd = GetConsoleWindow();
            if (hWnd != NULL) ShowWindow(hWnd, SW_HIDE);
        }
    }

    SetConsoleTitleA("Wazuh DLP - Endpoint Guardian");
    std::cout << "======================================================\n";
    std::cout << "   WAZUH DLP - ENDPOINT GUARDIAN (ZERO-TRUST MODE)    \n";
    std::cout << "======================================================\n\n";

    LoadBlacklist();
    WriteToLog("INFO: Endpoint Guardian Daemon started (Zero-Trust Mode).");

    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);

    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (hKeyboardHook == NULL) {
        WriteToLog("ERROR: Failed to install Keyboard Hook.");
        return 1;
    }

    hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseProc, NULL, 0);
    if (hMouseHook == NULL) {
        WriteToLog("ERROR: Failed to install Mouse Hook.");
    }

    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = HiddenWindowProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "WazuhDLPHiddenWindow";
    RegisterClassA(&wc);
    hHiddenWindow = CreateWindowExA(0, wc.lpszClassName, "Hidden", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    AddClipboardFormatListener(hHiddenWindow);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    RemoveClipboardFormatListener(hHiddenWindow);
    UnhookWindowsHookEx(hKeyboardHook);
    UnhookWindowsHookEx(hMouseHook);
    return 0;
}
```
