## III. Ngăn copy nội dung nhạy cảm tới môi trường không kiểm soát:
### 1. Mục tiêu và ứng dụng:
- **Mục tiêu:** Dựng lớp phòng thủ cuối cùng trên máy trạm (Endpoint) nhằm ngăn user cố tình hoặc vô ý copy data nhạy cảm từ tài liệu nội bộ và paste ra môi trường không an toàn.
- **Ứng dụng:**
    - **Bảo vệ Zero-Trust:** Hệ thống chỉ cho phép dán dữ liệu nhạy cảm giữa phần mềm nội bộ được phê duyệt. Bất kỳ nỗ lực dán nào sang ứng dụng bên ngoài đều bị chặn.
    - **Ngăn chặn theo thời gian thực:** Xóa sạch bộ nhớ đệm trong tích tắc trước khi lệnh paste kịp thực thi tới hệ điều hành.
    - **Truy vết ngữ cảnh cấp độ CISO (Context-Aware Forensics):** Cung cấp cho đội ngũ SOC bức tranh toàn cảnh về sự cố, trả lời chính xác câu hỏi: "Dữ liệu gì đã bị copy từ nơi nào, và suýt bị tuồn ra chỗ nào?".

### 2. Nguyên lý hoạt động
- **Sơ đồ luồng data:**
[User Copy Action (`Ctrl` + `C`)] ➔ [C++ Clipboard Listener] ➔ [YARA Engine Scan] ➔ [User Paste Action (`Ctrl` + `V`/Mouse)] ➔ [Zero-Trust Context Extraction] ➔ [RAM Wipe & Dashboard Alert]
- **Giải thích sơ đồ:**
    - **[User Copy Action (`Ctrl` + `C`)]**
User bôi đen một đoạn văn bản chứa nội dung nhạy cảm trên màn hình và thực hiện Copy. Dữ liệu lập tức được hệ điều hành Windows nạp vào bộ nhớ đệm RAM.
    - **[C++ Clipboard Listener]:**
    Chương trình bảo vệ `ScreenGuard.exe` (chạy ngầm bằng C++) sử dụng API `AddClipboardFormatListener` của Windows. Ngay khi bộ nhớ đệm có sự thay đổi, "cảm biến" lập tức bị đánh thức và trích xuất đoạn văn bản vừa copy ra khỏi RAM.
    - **[YARA Engine Scan]:**
    C++ đẩy đoạn văn bản qua tool YARA (`yara64.exe`) để đối chiếu với rules `sensitive_data.yar`.
        - Nếu an toàn: Hệ thống bỏ qua, user copy-paste bình thường.
        - Nếu có mã độc/data nhạy cảm: Hệ thống ghi nhận trạng thái `isClipboardToxic = true`, đồng thời dùng hàm `GetForegroundWindow()` để chụp lại ngay lập tức ứng dụng nguồn (VD: `notepad.exe`) và title nguồn (VD: `Danh_sach_KH.txt`) lưu vào bộ nhớ tạm.
    - **[User Paste Action (`Ctrl` + `V`/Mouse)]:**
    User chuyển sang ứng dụng khác (Ví dụ: Microsoft Edge) và cố gắng thực hiện lệnh Paste.
    - **[Zero-Trust Context Extraction]:**
    Các lưỡi câu ở tầng sâu của C++ (`WH_KEYBOARD_LL` và `WH_MOUSE_LL`) bắt hành động này trước khi Windows kịp xử lý, hệ thống sẽ kiểm tra ứng dụng hiện tại đang mở là gì:
        - Nếu là ứng dụng an toàn nằm trong danh sách Trắng (`TRUSTED_APPS`), lệnh Paste được đi qua.
        - Nếu là ứng dụng không tin cậy (như Chrome, Edge), hệ thống xác định đây là hành vi vi phạm. Nó dùng Windows API chụp lại Ứng dụng đích (`msedge.exe`) và Title đích (được làm sạch đuôi rác, VD: Google Gemini).
    - **[RAM Wipe & Dashboard Alert]:**
    Ngay khoảnh khắc phát hiện vi phạm, hệ thống thực thi hai hành động đồng thời:
        - Tiêu hủy data: Gọi hàm `EmptyClipboard()`, lập tức xóa trắng bộ nhớ đệm. Lệnh dán của user bị nuốt và không có data xuất hiện trên màn hình đích. Một pop-up cảnh báo xuất hiện.
        - Ghi Log Ngữ cảnh: Chuỗi sự kiện hoàn chỉnh (gồm nguồn và đích) được định dạng chuẩn `Syslog` và ghi vào `yara_debug.log`. Wazuh Agent gom log đẩy lên Manager. Giao diện Red Team Dashboard phân tách chuỗi log và vẽ ra sơ đồ luồng đi của dữ liệu cực kỳ trực quan cho SOC.

### 3. Cách cấu hình:
#### a) Tích hợp chức năng với chương trình `ScreenGuard.exe` tạo ở phần screenshot block trước
- Tải [Visual Studio](https://visualstudio.microsoft.com/downloads/) rồi mở file `.exe` vừa tải, đợi install và chọn mỗi `Desktop development with C++` để tải:
![image](https://hackmd.io/_uploads/S12jPS4iZg.png)
![image](https://hackmd.io/_uploads/Hy2TvB4jZl.png)
- Mở Visual Studio, đăng nhập, chọn `Create a new project` >>> `Console App (C++)`.
- Đăt tên project là `Screen_And_Clipboard`, chọn `Create` và đưa đoạn code sau vào:
``` cpp
#define _CRT_SECURE_NO_WARNINGS // Tắt cảnh báo localtime của Visual Studio

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
#include <shlobj.h> // [BỔ SUNG] Thư viện để xử lý kéo thả / copy file (HDROP)

struct BlacklistEntry {
    std::string originalPath;
    std::string keyword;
};

// --- GLOBAL VARIABLES ---
HHOOK hKeyboardHook;
HHOOK hMouseHook;
bool isSensitiveDataOnScreen = false;
std::string currentSensitiveWindowTitle = "";
std::string currentMatchedPath = "";
std::string currentProcessName = "";

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

const std::string TRUSTED_APPS[] = { "winword.exe", "excel.exe", "notepad.exe", "explorer.exe", "screen_and_clipboard.exe", "screenguard.exe", "cmd.exe", "powershell.exe" };

HWND hHiddenWindow = NULL;

int toxicCopyCount = 0;
std::chrono::time_point<std::chrono::system_clock> firstToxicCopyTime;
bool isClipboardOverrideActive = false;
std::chrono::time_point<std::chrono::system_clock> clipboardOverrideStartTime;
const int MAX_COPY_ALLOWED = 10;
const int COPY_TIME_WINDOW_SECONDS = 30;
const int CLIPBOARD_DISABLE_DURATION_SECONDS = 60;

std::unordered_map<std::string, FILETIME> fileModCache;

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

bool VerifyFileWithYara(const std::string& path) {
    std::string cmd = "\"" + YARA_EXE + " -w " + YARA_RULE + " \"" + path + "\" 2>&1\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return true;

    char buffer[128];
    std::string result = "";
    while (fgets(buffer, 128, pipe) != NULL) {
        result += buffer;
    }
    _pclose(pipe);
    return result.find("Detect_Sensitive_Info") != std::string::npos;
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

                FILETIME currentModTime = fileInfo.ftLastWriteTime;
                bool needsYaraScan = true;

                if (fileModCache.find(path) != fileModCache.end()) {
                    if (CompareFileTime(&fileModCache[path], &currentModTime) == 0) {
                        needsYaraScan = false;
                    }
                }

                if (needsYaraScan) {
                    std::cout << "[DELTA-SCAN] File modified or new. Scanning: " << path << "\n";
                    if (!VerifyFileWithYara(path)) {
                        listChanged = true;
                        fileModCache.erase(path);
                        std::cout << "[SELF-HEAL] File is clean. Removing from Blacklist: " << path << "\n";
                        WriteToLog("INFO: Data Lineage: Content cleaned by user. Removed from Blacklist [" + path + "]");
                        continue;
                    }
                    else {
                        fileModCache[path] = currentModTime;
                    }
                }
                survivingPaths.push_back(path);
            }
            else {
                listChanged = true;
                fileModCache.erase(path);
                std::cout << "[SELF-HEAL] File deleted. Removing from Blacklist: " << path << "\n";
                WriteToLog("INFO: Data Lineage: File deleted. Removed from Blacklist [" + path + "]");
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

void AddToBlacklistDirect(const std::string& newPath) {
    if (newPath == "Unknown Window" || newPath == "Unknown Tab" || newPath.length() < 3) return;

    for (const auto& entry : sensitiveEntries) {
        if (entry.originalPath == newPath) return;
    }

    std::ofstream file(BLACKLIST_FILE, std::ios_base::app);
    if (file.is_open()) {
        file << newPath << "\n";
        file.close();
        std::cout << "[DATA LINEAGE] Added new file to Blacklist: " << newPath << "\n";
        WriteToLog("INFO: Data Lineage tracking triggered. Added to Blacklist: [" + newPath + "]");
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

                size_t dotPos = filename.find_last_of(".");
                if (dotPos != std::string::npos) {
                    filename = filename.substr(0, dotPos);
                }

                entry.keyword = toLowerCase(filename);
                if (!entry.keyword.empty()) {
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

// --- [BỔ SUNG] HÀM KIỂM TRA COPY FILE TRONG CLIPBOARD ---
bool CheckClipboardForToxicFiles() {
    bool foundToxicFile = false;
    for (int i = 0; i < 3; ++i) {
        if (OpenClipboard(nullptr)) {
            // Kiểm tra xem Clipboard có đang chứa định dạng File (HDROP) không
            HANDLE hData = GetClipboardData(CF_HDROP);
            if (hData) {
                HDROP hDrop = static_cast<HDROP>(GlobalLock(hData));
                if (hDrop) {
                    // Lấy số lượng file đang được copy
                    UINT fileCount = DragQueryFileA(hDrop, 0xFFFFFFFF, NULL, 0);
                    char filePath[MAX_PATH];

                    // Quét từng file xem có nằm trong Blacklist không
                    for (UINT j = 0; j < fileCount; ++j) {
                        if (DragQueryFileA(hDrop, j, filePath, MAX_PATH)) {
                            std::string pathStr = std::string(filePath);

                            // Chuyển về chữ thường để so sánh cho chắc
                            std::string pathLower = toLowerCase(pathStr);

                            for (const auto& entry : sensitiveEntries) {
                                std::string entryLower = toLowerCase(entry.originalPath);
                                if (pathLower == entryLower) {
                                    std::cout << "[DLP] SENSITIVE FILE COPIED TO CLIPBOARD: " << pathStr << "\n";
                                    toxicSourceApp = "Windows Explorer (File Copy)";
                                    toxicSourceTitle = pathStr;
                                    foundToxicFile = true;
                                    break; // Chỉ cần 1 file độc là đủ chặn cả cụm
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

        // [BỔ SUNG] 1. ƯU TIÊN KIỂM TRA COPY FILE TRƯỚC
        if (CheckClipboardForToxicFiles()) {
            isClipboardToxic = true;
            std::cout << "[DLP] ASYNC SCAN: Toxic FILE detected in clipboard. Flag SET.\n";
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }

        // 2. SAU ĐÓ MỚI ĐẾN KIỂM TRA COPY CHỮ BẰNG YARA (LOGIC CŨ)
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
                        else {
                            if (windowTitle != "Unknown Tab") {
                                AddToBlacklistDirect(windowTitle);
                            }
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
                    else {
                        if (windowTitle != "Unknown Tab") {
                            AddToBlacklistDirect(windowTitle);
                        }
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

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    bool* foundSensitive = (bool*)lParam;

    if (IsWindowVisible(hwnd) && !IsIconic(hwnd)) {
        char windowTitle[512];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        std::string titleStr = toLowerCase(std::string(windowTitle));

        if (!titleStr.empty()) {
            for (const BlacklistEntry& entry : sensitiveEntries) {
                if (titleStr.find(entry.keyword) != std::string::npos) {
                    *foundSensitive = true;
                    currentSensitiveWindowTitle = std::string(windowTitle);
                    currentMatchedPath = entry.originalPath;
                    currentProcessName = GetProcessNameFromHwnd(hwnd);
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
- Ở thanh công cụ trên cùng Visual Studio, chuyển Build từ `Debug` sang `Release`, chuyển nền tảng kế bên sang `x64` (máy trạm đa số là 64-bit và `yara64.exe` cũng là 64-bit).
![Ảnh chụp màn hình 2026-03-28 021606](https://hackmd.io/_uploads/Hy5xuLEjbl.png)
- Nhấn `Ctrl` + `Shift` + `B` (hay vào `Build` >>> `Build Solution`) để biên dịch.
![image](https://hackmd.io/_uploads/Bkuy_UNsbx.png)
File `.exe` sau biên dịch nằm ở `C:\Users\Ha Nguyen\source\repos\Screen_And_Clipboard\x64\Release\Screen_And_Clipboard.exe`.
- Tạo `blacklist.txt` trong `C:\Users\Public` chứa keywords nhạy cảm, mỗi keyword ở một dòng.
![image](https://hackmd.io/_uploads/S1W3DaNiWg.png)
- Cấu hình Persistence (duy trì hoạt động bằng Scheduled Tasks): Chạy nền ứng dụng trên Endpoint, vì là chương trình bảo vệ nên cần chạy ngầm và không hiện cửa sổ đen console gây vướng cho user.
    - Copy file `Screen_And_Clipboard.exe` vừa build ra `C:\DLP\Screen_And_Clipboard.exe`.
    - Trong Command Prompt quyền admin chạy lần lượt command:
    ``` cmd
    schtasks /create /tn "ScreenGuard" /tr "'C:\DLP\Screen_And_Clipboard.exe' -hide" /sc onlogon /rl highest /f
    schtasks /change /tn "ScreenGuard" /it
    ```
    ![image](https://hackmd.io/_uploads/BJXkYT4oWe.png)
    Ngay sau khi chạy command, file `C:\Users\Public\yara_debug.log` xuất hiện.
    - Check Task Scheduler để xem tiến trình đã chạy ngầm chưa.
    ![image](https://hackmd.io/_uploads/ByOJc6NsWe.png)
- Cách hoạt động:
    - Chức năng screenshot:
        - Liên tục theo dõi màn hình (`EnumWindowsProc` kết hợp với `!IsIconic(hwnd)`. Nó chỉ kích hoạt bảo vệ khi file nhạy cảm đang thực sự hiển thị trên màn hình. Nếu user thu nhỏ file xuống Taskbar, "đôi mắt" này sẽ bỏ qua để trả lại quyền riêng tư cho user).
        - Nếu thấy user mở tài liệu mật thì lập tức tước vũ khí (phím chụp màn hình, phần mềm Snipping Tool) (Khi phím `PrtScn` được bấm, hàm này kiểm tra biến `isSensitiveDataOnScreen`. Nếu đang có dữ liệu mật, nó trả về giá trị `1`. Trong Windows API, trả về `1` có nghĩa là: "Tôi đã xử lý phím này rồi, các ứng dụng khác (kể cả Windows) đừng quan tâm đến nó nữa". Kết quả là phím chụp màn hình bị bốc hơi hoàn toàn) đưa ra cảnh báo. Và khi chặn thành công sẽ ghi log vào file log chung `yara_debug`.
    - Chức năng clipboard:
        - Khi user copy, data được nạp vào RAM, do có hàm API `AddClipboardFormatListener` nên nó đánh thức chương trình, chương trình trích xuất data vừa copy ra khỏi RAM, đồng thời gọi YARA với bộ rule đã chuẩn bị trước.
        - Nếu data nhạy cảm thì tạo một flag toxic cho clipboard, lúc này data vẫn paste bình thường, chỉ khi user dán vào ứng dụng khác thì tính năng của `Screen_And_Clipboard.exe` là `WH_KEYBOARD_LL`, `WH_MOUSE_LL` và cơ chế Zero Trust sẽ dựa theo whitelist để đối chiếu thay vì lập blacklist cho các ứng dụng không được phép paste. Ứng dụng không thuộc whitelist sẽ bị tiêu hủy data và lập tức xóa trắng bộ nhớ đệm.
        - Lệnh dán của user bị nuốt và không có dữ liệu nào xuất hiện trên màn hình đích. Một pop-up cảnh báo xuất hiện.

#### b) Cấu hình Wazuh-Manager (`local_rules.xml`):
Mục đích: Nhận diện chuỗi log do C++ gửi lên để đẩy log từ endpoint (C++) lên SIEM (Wazuh Manager) và phân loại thành cảnh báo.
- Vào Wazuh >>> `Management` >>> `Rules` >>> `Manage rules` >>> `local_rules.xml` và thêm rules, sau đó restart wazuh-manager:
![image](https://hackmd.io/_uploads/HklIoZHibx.png)
``` xml
<group name="local,syslog,sshd,">
  <!-- ============================================== -->
  <!-- CLIPBOARD LOG RULES (DATA-IN-MOTION RAM)       -->
  <!-- ============================================== -->
  
  <!-- Rule 100018: Detect Malicious Paste (CISO Context Logging) -->
  <rule id="100018" level="9">
    <decoded_as>windows-date-format</decoded_as>
    <match>wazuh-dlp: alert - Clipboard Blocked</match>
    <description>DLP Alert: Sensitive data copy attempt to an untrusted application blocked (Context Logged).</description>
    <group>dlp,clipboard,context_aware,</group>
  </rule>

  <!-- Rule 100019: Detect Secret Override (10 consecutive copies) -->
  <rule id="100019" level="10">
    <decoded_as>windows-date-format</decoded_as>
    <match>wazuh-dlp: alert - Secret clipboard override</match>
    <description>DLP Warning: User activated emergency clipboard override (10 consecutive copies detected).</description>
    <group>dlp,clipboard,override,</group>
  </rule>
    
  <rule id="100010" level="12">
    <match>wazuh-yara: alert</match>
    <description>DLP Alert: YARA detected sensitive data on endpoint.</description>
    <group>dlp,yara,sensitive_data,</group>
  </rule>

</group>
```
![image](https://hackmd.io/_uploads/S1my3-So-x.png)

#### c) Chỉnh sửa lại `app.py` để phù hợp với chương trình:
Chạy lần lượt các command sau trong Linux Server:
``` ubuntu
cd ~/wazuh-middleware
source venv/bin/activate
nano app.py
```
``` py
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import urllib3
import json
import re
import os
from pathlib import Path

QUARANTINE_REGISTRY = "/home/kanrorikakemem/wazuh-middleware/quarantine_registry.json"

def load_registry():
    if not os.path.exists(QUARANTINE_REGISTRY):
        return {}
    try:
        with open(QUARANTINE_REGISTRY, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_registry(data):
    with open(QUARANTINE_REGISTRY, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# Disable security warnings when calling Wazuh API with a self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ==========================================
# WAZUH CONNECTION CONFIGURATION
# ==========================================
WAZUH_SERVER_IP = "192.168.100.205"

WAZUH_API_PORT = 55000
WAZUH_API_USER = "wazuh"
WAZUH_API_PASS = "Pb5PeAgURdmPE+gNlThICtEUbv4zhuuK"

WAZUH_INDEXER_PORT = 9200
WAZUH_INDEXER_USER = "admin"
WAZUH_INDEXER_PASS = "2aCkDq*lFdmkjv.OGWXQOp7muQCG3sbm"

def get_wazuh_token():
    url = f"https://{WAZUH_SERVER_IP}:{WAZUH_API_PORT}/security/user/authenticate"
    try:
        response = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
        if response.status_code == 200:
            return response.json()['data']['token']
        print(f"Error retrieving token: {response.text}")
        return None
    except Exception as e:
        print(f"Failed to connect to Wazuh API: {e}")
        return None

# ==========================================
# ENDPOINT 1: TRIGGER SCAN FROM WEB
# ==========================================
@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    data = request.json
    agent_id = data.get('agent_id', '006')
    scan_type = data.get('scan_type', 'quick')

    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 401

    command_name = "win_yara_quick0" if scan_type == "quick" else "win_yara_full0"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"https://{WAZUH_SERVER_IP}:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    
    payload = {
        "command": command_name
    }

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        wazuh_response = response.json()
        
        if response.status_code != 200:
            return jsonify({"error": f"Wazuh rejected the command: {wazuh_response}"}), response.status_code
            
        return jsonify(wazuh_response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# ENDPOINT 3: QUARANTINE FILE - RAW PATH
# ==========================================
@app.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    data = request.json
    agent_id = data.get('agent_id', '006')
    file_path = data.get('file_path')

    if not file_path:
        return jsonify({"error": "Missing file path for quarantine"}), 400

    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 401

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"https://{WAZUH_SERVER_IP}:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    
    # Pass the raw path directly without encoding
    payload = {
        "command": "win_quarantine0",
        "arguments": [file_path]
    }

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        wazuh_response = response.json()
        
        if response.status_code != 200:
            error_msg = wazuh_response.get("message", str(wazuh_response))
            print(f"\n[WAZUH API ERROR] Port {WAZUH_API_PORT} reported an error: {error_msg}\n")
            return jsonify({"error": f"Wazuh rejected the command: {error_msg}"}), response.status_code
        
         # Luu vao registry
        from datetime import datetime
        registry = load_registry()
        agent_key = agent_id
        if agent_key not in registry:
            registry[agent_key] = []
        
        file_name = file_path.split('\\')[-1].split('/')[-1]
        registry[agent_key].append({
            "original_path": file_path,
            "original_name": file_name,
            "quarantine_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "status": "quarantined"
        })
        save_registry(registry)
        print(f"[REGISTRY] Saved quarantine entry: {file_path}")
        
        return jsonify(wazuh_response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# ENDPOINT 2: FETCH DLP ALERTS FROM INDEXER
# ==========================================
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    url = f"https://{WAZUH_SERVER_IP}:{WAZUH_INDEXER_PORT}/wazuh-alerts-*/_search"

    query = {
        "size": 70, 
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"term": {"rule.id": "100010"}}, # YARA Scan Alert
                    {"term": {"rule.id": "100011"}}, # Screenshot Blocked
                    {"term": {"rule.id": "100012"}}, # Emergency Override
                    {"term": {"rule.id": "100016"}}, # Sensitive file in USB
                    {"term": {"rule.id": "100017"}}, # Successfully delete file in USB
                    {"term": {"rule.id": "100018"}}, # Clipboard Blocked (Context Log)
                    {"term": {"rule.id": "100019"}}  # Clipboard Secret Override
                ],
                "minimum_should_match": 1
            }
        }
    }

    try:
        response = requests.get(
            url,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
            json=query,
            verify=False
        )
        
        if response.status_code != 200:
            return jsonify({"error": "Failed to query Indexer", "details": response.text}), response.status_code

        data = response.json()
        clean_alerts = []

        if 'hits' in data and 'hits' in data['hits']:
            for hit in data['hits']['hits']:
                source = hit['_source']
                
                full_log = source.get('full_log', '')
                file_path = "Unknown"

                # NEW LOGIC: SMART PATH EXTRACTION FOR MULTIPLE LOG TYPES
                
                # 1. Logs from ScreenGuard C++: "Source Path: [C:\...]" or "Target Path: [C:\...]"
                if 'Source Path: [' in full_log:
                    file_path = full_log.split('Source Path: [')[-1].split(']')[0]
                elif 'Target Path: [' in full_log:
                    file_path = full_log.split('Target Path: [')[-1].split(']')[0]
                
                # 2. Logs from YARA Scan PowerShell: "Found Sensitive Data in C:\..."
                elif ' in ' in full_log:
                    file_path = full_log.split(' in ')[-1].strip()
                    
                # Clean up the path (remove extra spaces and brackets)
                file_path = file_path.strip()

                clean_alerts.append({
                    "id": hit['_id'],
                    "time": source.get('timestamp', '').replace('T', ' ')[:19],
                    "target": file_path,
                    "rule": source.get('rule', {}).get('description', 'DLP Alert'),
                    "level": source.get('rule', {}).get('level', 12),
                    "agent_name": source.get('agent', {}).get('name', 'N/A'),
                    "actionTaken": "Alerted", 
                    "full_log": full_log
                })

        return jsonify(clean_alerts), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# ENDPOINT: RESTORE FILE FROM QUARANTINE
# ==========================================
@app.route('/api/restore', methods=['POST'])
def restore_file():
    import urllib.parse
    data = request.json
    agent_id = data.get('agent_id', '006')
    quarantine_filename = data.get('quarantine_filename')

    if not quarantine_filename:
        return jsonify({"error": "Missing quarantine_filename"}), 400

    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 401

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"

    # URL encode tên file giống cách quarantine hoạt động
    encoded_filename = urllib.parse.quote(quarantine_filename, safe='')

    payload = {
        "command": "win_restore0",
        "custom": True,
        "arguments": [encoded_filename]
    }

    print(f"[RESTORE] Agent={agent_id}, File={quarantine_filename}")
    print(f"[RESTORE] Encoded={encoded_filename}")
    print(f"[RESTORE] Payload={payload}")

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        wazuh_response = response.json()
        print(f"[WAZUH RESPONSE] {wazuh_response}")

        if response.status_code != 200:
            error_msg = wazuh_response.get("message", str(wazuh_response))
            return jsonify({"error": f"Wazuh rejected: {error_msg}"}), response.status_code

        # Cap nhat registry
        registry = load_registry()
        agent_key = agent_id
        if agent_key in registry:
            registry[agent_key] = [
                e for e in registry[agent_key]
                if e.get('original_name') != quarantine_filename
                and not quarantine_filename.endswith(e.get('original_name', ''))
            ]
            save_registry(registry)
            print(f"[REGISTRY] Removed restore entry: {quarantine_filename}")
        
        return jsonify(wazuh_response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# ENDPOINT: LIST QUARANTINE FILES
# ==========================================
@app.route('/api/list_quarantine', methods=['POST'])
def list_quarantine():
    data = request.json
    agent_id = data.get('agent_id', '006')
    
    registry = load_registry()
    files = registry.get(agent_id, [])
    
    # Chi lay nhung file con status quarantined
    active = [f for f in files if f.get('status') == 'quarantined']
    
    return jsonify({"files": active}), 200    

if __name__ == '__main__':
    print(f"Starting Wazuh DLP Middleware API on port 5000... (Targeting Wazuh at {WAZUH_SERVER_IP})")
    app.run(host='0.0.0.0', port=5000, debug=True)
```

#### d) Sửa dashboard để đọc log đường dẫn cho clipboard:
Chạy lần lượt các command:
``` ubuntu
sudo rm /var/www/html/index.html
sudo nano /var/www/html/index.html
```
``` html
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh DLP - Red Team Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #020202; color: #00ff41; font-family: 'Courier Prime', monospace; }
        .red-glow { color: #ff0000; text-shadow: 0 0 8px #ff0000; }
        .green-glow { text-shadow: 0 0 8px #00ff41; }
        .border-neon { border: 1px solid #00ff41; box-shadow: 0 0 10px rgba(0,255,65,0.1) inset; }
        
        .scanline {
            width: 100%; height: 100px; z-index: 100; position: absolute; pointer-events: none;
            background: linear-gradient(0deg, rgba(0,0,0,0) 0%, rgba(0,255,65,0.1) 50%, rgba(0,0,0,0) 100%);
            opacity: 0.1; animation: scanline 6s linear infinite;
        }
        @keyframes scanline { 0% { top: -100px; } 100% { top: 100%; } }
        
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #000; border-left: 1px solid #00ff41; }
        ::-webkit-scrollbar-thumb { background: #00ff41; }

        table { width: 100%; border-collapse: collapse; }
        th { border-bottom: 2px dashed #00ff41; padding: 10px; text-align: left; font-weight: bold; position: sticky; top: 0; background: #050505; z-index: 10;}
        td { border-bottom: 1px solid rgba(0, 255, 65, 0.2); padding: 10px; word-break: break-all;}
        tr:hover { background-color: rgba(0, 255, 65, 0.1); }
    </style>
</head>
<body class="h-screen flex flex-col p-4 relative overflow-hidden bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 via-black to-black">
    <div class="scanline"></div>

    <!-- HEADER -->
    <header class="flex justify-between items-center pb-2 border-b border-[#00ff41] border-dashed mb-4 z-10 shrink-0">
        <div class="flex items-center gap-4">
            <div class="w-12 h-12 border-2 border-[#00ff41] rounded-full flex items-center justify-center animate-spin" style="animation-duration: 3s;">
                <div class="w-8 h-8 border border-[#00ff41] rounded-full border-t-transparent"></div>
            </div>
            <div>
                <h1 class="text-2xl font-bold tracking-widest green-glow">WAZUH DLP_CONSOLE.EXE</h1>
                <p class="text-xs uppercase opacity-70">Data Loss Prevention - Tactical View</p>
            </div>
        </div>
        <div class="text-right border-neon p-2 bg-black flex gap-6 items-center">
            <div>
                <div class="text-xs opacity-70">STATUS</div>
                <div class="text-sm font-bold green-glow">ONLINE</div>
            </div>
            <div>
                <div class="text-xs opacity-70">MANAGER IP</div>
                <!-- Đã cập nhật Manager IP ở đây -->
                <div class="text-sm">192.168.100.205</div>
            </div>
            <div>
                <div class="text-xs opacity-70">DEFCON</div>
                <div class="text-sm red-glow font-bold animate-pulse">LEVEL 2</div>
            </div>
        </div>
    </header>

    <!-- MAIN CONTENT -->
    <main class="flex-1 flex gap-4 z-10 overflow-hidden">
        
        <!-- SIDEBAR -->
        <div class="w-80 flex flex-col gap-4 shrink-0">
            <div class="border-neon p-4 bg-black/60">
                <h3 class="border-b border-[#00ff41] pb-1 mb-3 uppercase text-sm font-bold">> EXECUTION TARGET</h3>
                <select id="agentSelect" class="w-full bg-black border border-[#00ff41] p-1 text-[#00ff41] outline-none text-sm mb-4">
                    <option value="006">Agent 006 (Windows_Virtual)</option>
                </select>
                
                <h3 class="border-b border-[#00ff41] pb-1 mb-3 uppercase text-sm font-bold">> OVERRIDE DIRECTIVES</h3>
                <button onclick="triggerScan('quick')" class="w-full text-left py-2 px-3 border border-[#00ff41] hover:bg-[#00ff41] hover:text-black transition mb-2 font-bold">
                    [+] INIT QUICK SCAN
                </button>
                <button onclick="triggerScan('full')" class="w-full text-left py-2 px-3 border border-[#00ff41] hover:bg-[#00ff41] hover:text-black transition mb-2 font-bold">
                    [!] INIT FULL SCAN
                </button>
            </div>

            <div class="border-neon p-4 bg-black/60 flex-1 flex flex-col">
                <h3 class="border-b border-[#00ff41] pb-1 mb-3 uppercase text-sm font-bold">> THREAT SIGNATURES</h3>
                <div class="flex-1 relative flex items-center justify-center min-h-[200px]">
                    <canvas id="ruleChart"></canvas>
                </div>
                <div id="totalLogsCounter" class="mt-4 border border-[#00ff41] p-2 text-center text-xs">
                    TOTAL ALERTS DETECTED: 0
                </div>
            </div>
        </div>

        <!-- BẢNG LOGS & TABS -->
        <div class="flex-1 border-neon bg-black/80 flex flex-col relative overflow-hidden">
            
            <!-- TOOLBAR: TABS & SEARCH -->
            <div class="bg-black border-b border-[#00ff41] p-2 flex justify-between items-center shrink-0">
                <!-- Tabs -->
                <div class="flex gap-2">
                    <button onclick="switchTab('all')" id="tab-all" class="text-black bg-[#00ff41] border border-[#00ff41] px-4 py-1 font-bold transition text-sm">
                        [ LIVE_FEED ]
                    </button>
                    <button onclick="switchTab('quarantine')" id="tab-quarantine" class="text-[#00ff41] border border-[#00ff41] hover:bg-[#00ff41]/20 px-4 py-1 font-bold transition text-sm">
                        [ QUARANTINE_VAULT ]
                    </button>
                </div>
                
                <!-- Search & Refresh -->
                <div class="flex items-center gap-4 w-1/2 justify-end">
                    <input type="text" id="searchInput" placeholder="Search paths, rules..." class="bg-black text-[#00ff41] border border-[#00ff41] px-2 py-1 outline-none text-sm w-2/3 font-normal" onkeyup="filterLogs()">
                    <button onclick="fetchLogs()" class="border border-[#00ff41] px-3 py-1 hover:bg-[#00ff41] hover:text-black transition text-sm font-bold">
                        [ REFRESH ]
                    </button>
                </div>
            </div>
            
            <!-- Table Container -->
            <div class="flex-1 overflow-auto p-2">
                <table id="logsTable">
                    <thead>
                        <tr>
                            <th class="w-1/6">TIMESTAMP</th>
                            <th class="w-2/6">TARGET (FILE PATH)</th>
                            <th class="w-2/6">RULE NAME</th>
                            <th class="w-1/12 text-center">SEVERITY</th>
                            <th class="w-1/6 text-center">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="logsBody" class="text-sm">
                        <tr><td colspan="5" class="text-center py-8 text-[#00ff41] animate-pulse">ESTABLISHING SECURE CONNECTION...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <!-- TOAST NOTIFICATION -->
    <div id="toastContainer" class="fixed bottom-4 right-4 flex flex-col gap-2 z-50"></div>

    <script>
        // Đã cập nhật API_URL thành IP mới của Middleware
        const API_URL = 'http://192.168.100.205:5000/api'; 
        
        let allLogsData = []; 
        let chartInstance = null;
        let currentTab = 'all'; 
        
        // BỘ NHỚ THÔNG MINH: Lưu lại danh sách các đường dẫn file đã bị cách ly
        let quarantinedPaths = new Set(); 
        // Map: original_path → quarantine_filename (để restore đúng file)
        let quarantinedFileMap = {};

        Chart.defaults.color = '#00ff41';
        Chart.defaults.font.family = "'Courier Prime', monospace";

        window.onload = () => {
            fetchLogs();
            setInterval(fetchLogs, 10000); // Tự làm mới sau 10s
        };

        // Hàm chuyển Tab
        function switchTab(tab) {
            currentTab = tab;
            const tabAll = document.getElementById('tab-all');
            const tabQ = document.getElementById('tab-quarantine');
            
            if (tab === 'all') {
                tabAll.className = "text-black bg-[#00ff41] border border-[#00ff41] px-4 py-1 font-bold transition text-sm";
                tabQ.className = "text-[#00ff41] border border-[#00ff41] hover:bg-[#00ff41]/20 px-4 py-1 font-bold transition text-sm";
            } else {
                tabQ.className = "text-black bg-[#00ff41] border border-[#00ff41] px-4 py-1 font-bold transition text-sm";
                tabAll.className = "text-[#00ff41] border border-[#00ff41] hover:bg-[#00ff41]/20 px-4 py-1 font-bold transition text-sm";
            }
            filterLogs(); // Cập nhật lại bảng
        }

        async function fetchLogs() {
            try {
                const response = await fetch(`${API_URL}/alerts`);
                if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
                const data = await response.json();
                
                allLogsData = Array.isArray(data) ? data : (data.logs || []);
                filterLogs(); // Gọi filterLogs thay vì renderTable để tôn trọng Tab hiện tại
                updateChart(allLogsData);
                
            } catch (error) {
                // Đã đổi thông báo lỗi sang Tiếng Anh
                document.getElementById('logsBody').innerHTML = `
                    <tr><td colspan="5" class="text-center py-8 text-red-500">
                        [!] CONNECTION ERROR: Cannot fetch data from Middleware.<br>
                        Details: ${error.message}
                    </td></tr>`;
            }
        }

        function filterLogs() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            
            // Lọc dữ liệu qua 2 màng lọc: Search Text và Tab Hiện Tại
            const displayLogs = allLogsData.filter(log => {
                const source = log._source || {};
                const rule = source.rule || {};
                const target = log.target || source.syscheck?.path || '';
                const ruleDesc = rule.description || log.rule || '';
                const fullLog = source.full_log || '';
                
                // 1. Màng lọc Search (bao gồm cả nội dung full_log để tìm tên file/app)
                const textMatch = `${ruleDesc} ${target} ${fullLog}`.toLowerCase().includes(searchTerm);
                
                // 2. Màng lọc Tab
                let tabMatch = true;
                if (currentTab === 'quarantine') {
                    // Nếu ở tab kho cách ly, chỉ hiện những file có đường dẫn nằm trong danh sách đã cách ly
                    tabMatch = quarantinedPaths.has(target);
                }
                
                return textMatch && tabMatch;
            });

            renderTable(displayLogs);
        }

        function renderTable(logs) {
            const tbody = document.getElementById('logsBody');
            tbody.innerHTML = '';

            if (logs.length === 0) {
                const emptyMsg = currentTab === 'quarantine' ? "VAULT IS EMPTY. NO FILES QUARANTINED." : "NO THREATS DETECTED. SYSTEM CLEAN.";
                tbody.innerHTML = `<tr><td colspan="5" class="text-center py-8 opacity-70">${emptyMsg}</td></tr>`;
                return;
            }

            logs.forEach(log => {
                const source = log._source || {};
                const rule = source.rule || {};
                
                let timestamp = source.timestamp || source['@timestamp'] || log.time || 'N/A';
                timestamp = timestamp.replace('T', ' ').substring(0, 19);

                const fullLogStr = log.full_log || source.full_log || '';
                let ruleName = rule.description || log.rule || 'Unknown Rule';
                
                let filePath = log.target || 'N/A';
                let targetDisplayHtml = '';
                let isClipboardViolation = false;
                let isUsbKilled = false;

                // KỊCH BẢN 1: LOG CLIPBOARD (Có Source và Destination)
                if (ruleName.includes('Clipboard Blocked') || ruleName.includes('chặn hành vi sao chép') || fullLogStr.includes('Clipboard Blocked')) {
                    
                    const sourceMatch = fullLogStr.match(/Source: \[(.*?)\]/);
                    const destMatch = fullLogStr.match(/Destination: \[(.*?)\]/);
                    
                    if (sourceMatch && destMatch) {
                        const sourceData = sourceMatch[1].split(' - ');
                        const destData = destMatch[1].split(' - ');
                        
                        const srcApp = sourceData[0] || 'Unknown';
                        const srcTitle = sourceData.slice(1).join(' - ') || 'N/A'; 
                        
                        const dstApp = destData[0] || 'Unknown';
                        const dstTitle = destData.slice(1).join(' - ') || 'N/A';

                        // HIỂN THỊ DẠNG HÀNG NGANG (Inline) ĐỒNG BỘ VỚI LOG DƯỚI
                        targetDisplayHtml = `<span class="font-bold text-sm break-all">
                            <span class="opacity-70">[${srcApp}]</span> ${srcTitle} 
                            <span class="text-red-500 font-bold mx-2">➔</span> 
                            <span class="opacity-70">[${dstApp}]</span> ${dstTitle}
                        </span>`;
                        
                        isClipboardViolation = true;
                        filePath = "CLIPBOARD_CONTEXT"; 
                    } else {
                         // FALLBACK DẠNG HÀNG NGANG KHI THIẾU LOG
                         targetDisplayHtml = `<span class="font-bold text-sm break-all text-yellow-500">
                            [N/A] <span class="mx-2">➔</span> [N/A] <i class="opacity-70">(API Missing Data)</i>
                         </span>`;
                         isClipboardViolation = true;
                         filePath = "CLIPBOARD_CONTEXT"; 
                    }
                } 
                // KỊCH BẢN 2: LOG FILE/USB BÌNH THƯỜNG
                else {
                    // Đổi 'Không xác định' thành 'Unknown' cho hợp logic backend
                    if (filePath === 'N/A' || filePath === 'Unknown') {
                        if (source.syscheck && source.syscheck.path) {
                            filePath = source.syscheck.path;
                        } else if (source.parameters && source.parameters.alert && source.parameters.alert.syscheck) {
                            filePath = source.parameters.alert.syscheck.path;
                        } else if (fullLogStr) {
                            let match = fullLogStr.match(/Source Path: \[(.*?)\]/);
                            if (match) filePath = match[1];
                            else {
                                match = fullLogStr.match(/Target Path: \[(.*?)\]/);
                                if (match) filePath = match[1];
                                else {
                                    match = fullLogStr.match(/in (C:\\[^\s]+)/);
                                    if (match) filePath = match[1];
                                    else {
                                        match = fullLogStr.match(/in (E:\\[^\s]+)/);
                                        if (match) filePath = match[1];
                                    }
                                }
                            }
                        }
                    }
                    targetDisplayHtml = `<span class="font-bold text-sm break-all">${filePath}</span>`;
                }

                if (fullLogStr.includes('action_success - USB file destroyed')) {
                    isUsbKilled = true;
                }

                let severityLevel = rule.level || log.level || 0;
                
                let severityHtml = `<span class="text-[#00ff41]">${severityLevel}</span>`;
                if (severityLevel >= 12) severityHtml = `<span class="red-glow font-bold text-lg">${severityLevel}</span>`;
                else if (severityLevel >= 7) severityHtml = `<span class="text-yellow-400 font-bold">${severityLevel}</span>`;
                
                // KIỂM TRA TRẠNG THÁI CÁCH LY & RENDER NÚT ACTION
                const isQuarantined = quarantinedPaths.has(filePath);
                let actionHtml = '';
                
                if (isClipboardViolation) {
                    actionHtml = `<span class="border border-[#00ff41] bg-black text-[#00ff41] px-2 py-1 text-[10px] font-bold shadow-[0_0_5px_#00ff41_inset]">[ RAM WIPED ]</span>`;
                } else if (isUsbKilled) {
                    actionHtml = `<span class="border border-red-500 bg-red-900/30 text-red-500 px-2 py-1 text-[10px] font-bold">[ TERMINATED ]</span>`;
                } else if (isQuarantined) {
                    // Tạo tên file quarantine từ đường dẫn gốc để gọi restore
                    const fileName = filePath.split('\\').pop();
                    const quarantineName = quarantinedFileMap[filePath] || '';
                    const restoreBtn = quarantineName 
                        ? `<button onclick="restoreFile('${quarantineName.replace(/'/g, "\\'")}')" 
                              class="border border-yellow-400 text-yellow-400 px-2 py-1 text-[10px] font-bold hover:bg-yellow-400 hover:text-black transition ml-1">
                              [ RESTORE ]
                           </button>`
                    : '';
                    actionHtml = `<span class="border border-[#00ff41] bg-green-900/30 text-[#00ff41] px-2 py-1 text-xs font-bold shadow-[0_0_5px_#00ff41_inset]">[ SECURED ]</span>`;
                } else if (filePath !== 'N/A' && filePath !== 'Unknown' && filePath !== 'CLIPBOARD_CONTEXT' && severityLevel >= 10) {
                    actionHtml = `<button onclick="quarantineFile('${filePath.replace(/\\/g, '\\\\')}')" class="border border-red-500 text-red-500 px-2 py-1 text-xs font-bold hover:bg-red-500 hover:text-white transition shadow-[0_0_5px_red_inset] animate-pulse">[ QUARANTINE ]</button>`;
                } else {
                    actionHtml = `<span class="text-gray-500 text-xs">-</span>`;
                }

                // Render dòng (Đã gỡ bỏ align-top để đồng bộ với các dòng khác)
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="opacity-80">${timestamp}</td>
                    <td>${targetDisplayHtml}</td>
                    <td class="opacity-80 text-xs">${ruleName}</td>
                    <td class="text-center">${severityHtml}</td>
                    <td class="text-center">${actionHtml}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function triggerScan(type) {
            const agentId = document.getElementById('agentSelect').value;
            showToast(`> DISPATCHING ${type.toUpperCase()} SCAN...`, "info");
            try {
                const response = await fetch(`${API_URL}/scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agent_id: agentId, scan_type: type })
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                showToast(`[OK] SCAN EXECUTING ON AGENT ${agentId}`, "success");
            } catch (error) {
                showToast(`[ERROR] API FAILED: ${error.message}`, "error");
            }
        }

        async function quarantineFile(filePath) {
            // Đã đổi thông báo xác nhận sang Tiếng Anh
            if (!confirm(`CONFIRM QUARANTINE FOR THIS FILE?\n\n${filePath}`)) return;
            
            const agentId = document.getElementById('agentSelect').value;
            showToast(`> INITIATING QUARANTINE PROTOCOL...`, "info");
            
            try {
                const response = await fetch(`${API_URL}/quarantine`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agent_id: agentId, file_path: filePath })
                });
                
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                
                showToast(`[OK] FILE LOCKED IN VAULT.`, "success");
                
                // NGAY LẬP TỨC: Đưa đường dẫn vào danh sách đen của UI
                quarantinedPaths.add(filePath);
                // Lưu mapping để restore sau: ta chưa biết tên quarantine lúc này
                // Dashboard sẽ cần user nhập hoặc lấy từ API listing
                // Tạm thời để trống, user dùng Telegram bot để restore
                quarantinedFileMap[filePath] = null;
                
                // Cập nhật lại bảng (nút đỏ sẽ hóa xanh, và nhảy sang tab Vault)
                filterLogs(); 
                
            } catch (error) {
                showToast(`[ERROR] QUARANTINE FAILED: ${error.message}`, "error");
            }
        }
        
        async function restoreFile(quarantineFilename) {
            if (!quarantineFilename) {
                showToast('[ERROR] No quarantine filename. Use Telegram bot: /restore 006 <filename>', 'error');
                return;
            }
            if (!confirm(`RESTORE THIS FILE FROM QUARANTINE?\n\n${quarantineFilename}\n\nFile will be YARA-scanned after restore.`)) return;

            const agentId = document.getElementById('agentSelect').value;
            showToast(`> INITIATING RESTORE PROTOCOL...`, "info");

            try {
                const response = await fetch(`${API_URL}/restore`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agent_id: agentId, quarantine_filename: quarantineFilename })
                });

                if (!response.ok) throw new Error(`HTTP ${response.status}`);

                showToast(`[OK] RESTORE COMMAND SENT. YARA RE-SCAN IN PROGRESS...`, "success");

                // Xóa khỏi danh sách quarantine trong UI
                for (const [path, qname] of Object.entries(quarantinedFileMap)) {
                    if (qname === quarantineFilename) {
                        quarantinedPaths.delete(path);
                        delete quarantinedFileMap[path];
                        break;
                    }
                }
                filterLogs();

            } catch (error) {
                showToast(`[ERROR] RESTORE FAILED: ${error.message}`, "error");
            }
        }

        function updateChart(logs) {
            document.getElementById('totalLogsCounter').innerText = `TOTAL ALERTS DETECTED: ${logs.length}`;
            const ruleCounts = {};
            logs.forEach(log => {
                const desc = log.rule || 'Unknown Rule';
                ruleCounts[desc] = (ruleCounts[desc] || 0) + 1;
            });
            const sortedRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);
            const labels = sortedRules.map(item => item[0].length > 25 ? item[0].substring(0, 25) + "..." : item[0]);
            const dataValues = sortedRules.map(item => item[1]);

            if (chartInstance) chartInstance.destroy();
            const ctx = document.getElementById('ruleChart').getContext('2d');
            chartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: dataValues,
                        backgroundColor: ['rgba(255, 0, 0, 0.7)', 'rgba(255, 165, 0, 0.7)', 'rgba(0, 255, 65, 0.7)'],
                        borderColor: '#00ff41',
                        borderWidth: 1,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, cutout: '60%',
                    plugins: { legend: { position: 'bottom', labels: { color: '#00ff41', boxWidth: 12, font: { size: 10, family: "'Courier Prime', monospace" } } } }
                }
            });
        }

        function showToast(message, type) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            let borderColor = type === "error" ? "border-red-500" : "border-[#00ff41]";
            let textColor = type === "error" ? "text-red-500" : "text-[#00ff41]";
            let shadow = type === "error" ? "shadow-[0_0_10px_red]" : "shadow-[0_0_10px_#00ff41]";

            toast.className = `border ${borderColor} bg-black ${textColor} px-4 py-2 font-bold text-sm ${shadow} animate-pulse flex items-center gap-2`;
            toast.innerHTML = `<span>></span> <span>${message}</span>`;
            
            container.appendChild(toast);
            setTimeout(() => {
                toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
                setTimeout(() => toast.remove(), 500);
            }, 4000);
        }
    </script>
</body>
</html>
```
- Đảm bảo `.html` vừa tạo có quyền đọc đúng và khởi động lại Nginx:
``` ubuntu
sudo chmod 644 /var/www/html/index.html
sudo chown www-data:www-data /var/www/html/index.html
sudo systemctl restart nginx
```

### 4. Demo
#### a) Chuẩn bị:
- Chạy lần lượt các command sau trong Linux Server:
    ```
    cd ~/wazuh-middleware
    source venv/bin/activate
    python3 app.py
    ```
    ![image](https://hackmd.io/_uploads/SyRBPUrobl.png)
Giữ nguyên cho Terminal trên chạy ngầm.
- Trên máy Windows, mở dashboard bằng cách truy cập `http://192.168.100.205` trên trình duyệt và vào tab `[ LIVE_FEED ]` để theo dõi:
![image](https://hackmd.io/_uploads/rkqI98riWe.png)
- Mở `screen_and_clipboard.exe` với quyền admin để hiện console, để sẵn đó để tiện theo dõi.
![image](https://hackmd.io/_uploads/r1Yc68Hs-x.png)
- Tạo file `Origin.txt` chứa dữ liệu nhạy cảm:
![image](https://hackmd.io/_uploads/rJJgaIrjZl.png)

#### b) Thực hiện:
- Bôi đen toàn bộ nội dung trong `Origin.txt` rồi copy, khi này log đã lưu lại, rồi thử paste ra file `.txt` khác thì vẫn paste được bình thường:
![image](https://hackmd.io/_uploads/r1yLY5Ssbg.png)
- Nếu paste ra trình duyệt, chẳng hạn ChatGPT:
![image](https://hackmd.io/_uploads/B1qQ95BiZe.png)
- Thông tin việc chặn được ghi lại trong log:
![image](https://hackmd.io/_uploads/H1-F59rsWg.png)
- Trên dashboard:
![image](https://hackmd.io/_uploads/BkGRhm8iZl.png)
