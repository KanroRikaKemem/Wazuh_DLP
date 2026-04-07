## II. Chức năng quét data tĩnh:
### 1. Mục tiêu và ứng dụng:
- **Mục tiêu:** Tạo trang web dành riêng cho DLP có chức năng scan, dashboard để dễ dàng theo dõi log và thu thập kết quả scan.
- **Ứng dụng:** Chức năng Scan cho phép quét folder bình thường không chứa file nhạy cảm để check xem user có để file sai nơi quy định không.

### 2. Nguyên lý hoạt động:
- **Sơ đồ:**
[Web Dashboard] ➔ [Middleware API (`app.py`)] ➔ [Wazuh Manager API] ➔ [Windows Agent (wazuh-execd)] ➔ [Trạm phóng (`.bat`) ] ➔ [PowerShell Script] ➔ [YARA Engine (Deep Scan)] ➔ [Log Collector] ➔ [Wazuh Manager (Alert)]
- **Giải thích sơ đồ:**
    - **Web Dashboard - Khởi xướng lệnh:** 
Admin chọn mục tiêu (Agent ID) và loại quét (Quick Scan/Full Scan) trên giao diện Web. Khi bấm nút, Web UI gửi một HTTP POST Request chứa thông tin lệnh tới Middleware.
    - **Middleware API (app.py) - Xử lý tại Middleware:**
Middleware (app.py chạy bằng Flask) tiếp nhận request rồi tiến hành xác thực (lấy JWT Token) với Wazuh Manager. Sau đó nó biên dịch yêu cầu thành chuẩn API của Wazuh (chỉ định `command win_yara_quick0` hoặc `win_yara_full0`) và đẩy lệnh qua port `55000`.
    - **Wazuh Manager API - Điều phối command:**
Wazuh Manager tiếp nhận API call, xác định agent mục tiêu đang online và đẩy bản tin Active Response qua kênh truyền tải bảo mật xuống máy trạm Windows.
    - **Windows Agent (wazuh-execd) - Tiếp nhận tại Agent:**
Tiến trình lõi wazuh-execd trên máy trạm Windows nhận bản tin rồi kiểm tra cấu hình nội bộ và xác định command cần chạy.
    - **Trạm phóng (`.bat`) - Kích hoạt trạm phóng:**
File `.bat` được chạy ẩn với quyền SYSTEM. Chức năng duy nhất là gọi trình thông dịch `powershell.exe` với cờ `-ExecutionPolicy ByPass` để vượt qua hàng rào bảo mật Execution Policy của hệ điều hành, nhằm khởi chạy file script chính (`.ps1`).
    - **Thiết lập môi trường quét:**
Script PowerShell (`yara_full_scan.ps1`) bắt đầu chạy. Nó tự động xác định thư mục cần quét (duyệt tất cả các user folder trong `C:\Users`). Script cũng kiểm tra sự hiện diện của YARA Engine, nếu thiếu thì tự động tải về từ Github và giải nén.
    - **YARA Engine (Deep Scan) - Phân tích data chuyên sâu:**
PowerShell nạp tập rule **sensitive_data.yar** và gọi `yara64.exe` để rà soát từng file.
        - Với file text thường: YARA quét trực tiếp.
        - Với file Office (`.docx`, `.xlsx`, `.pptx`): Kích hoạt cơ chế Deep Scan. Script tiến hành copy file ra thư mục `Temp`, đổi đuôi thành `.zip`, bung nén mã nguồn XML bên trong và ép YARA quét đệ quy toàn bộ thư mục vừa bung ra để bắt quả tang dữ liệu ẩn.
    - **Log Collector - Ghi nhật ký:**
Khi phát hiện file vi phạm (khớp pattern), script PowerShell tạo ra một bản ghi log chuẩn Syslog (Ví dụ: … wazuh-yara: alert - Found Sensitive Data…) và ghi đè nối tiếp vào file `C:\Users\Public\yara_debug.log`.
    - **Wazuh Manager (Alert) - Thu thập và Cảnh báo:**
Wazuh Log Collector (chạy ngầm trên Agent) lập tức đọc dòng log mới và gửi ngược về Server. Wazuh Manager giải mã, đối chiếu khớp với Rule ID và đẩy chuông báo động (alert) lên thẳng Dashboard của admin.

### 3. Các bước cấu hình:
#### a) Cấu hình ban đầu:
- Chạy `sudo nano /var/ossec/etc/ossec.conf` để thêm command mới cho chức năng scan và cách ly DLP:
    - Định nghĩa command:
    ``` ubuntu
      <command>
        <name>win_yara_quick</name>
        <executable>run_yara_quick.bat</executable>
      </command>

      <command>
        <name>win_yara_full</name>    
        <executable>run_yara_full.bat</executable>
      </command>

      <command>
        <name>win_quarantine</name>
        <executable>run_quarantine.bat</executable>
      </command>
      
      <command>
        <name>win_restore</name>
        <executable>run_restore.bat</executable>
      </command>
    ```
    - Kích hoạt để Manager nạp command:
    ``` ubuntu
      <active-response>
        <command>win_yara_quick</command>
        location>local</location>
      </active-response>

      <active-response>
        <command>win_yara_full</command>
        <location>local</location>
      </active-response>

      <active-response>
        <command>win_quarantine</command>
        location>local</location>
      </active-response>
      
      <active-response>
        <command>win_restore</command>
        <location>local</location>
      </active-response>
    ```
    - Khi thêm vào, Wazuh manager chạy command sẽ bắn thông tin đến agent để nó biết nên thực thi file nào.
    - Vào `C:\Program Files (x86)\ossec-agent\ossec.conf` và thêm:
    ``` conf
      <localfile>
        <location>active-response\active-responses.log</location>
        <log_format>syslog</log_format>
      </localfile>

      <localfile>
        <log_format>syslog</log_format>
        <location>C:\Users\Public\yara_debug.log</location>
      </localfile>

      <localfile>
        <location>C:\dlp_logs\dlp_alerts.log</location>
        <log_format>syslog</log_format>
      </localfile>
    ```
    - Ở trong phần `syscheck`, đảm bảo có:
    ``` conf
    <disabled>no</disabled>

    <directories realtime="yes" check_all="yes">C:\SecretData</directories>
    <directories realtime="yes" check_all="yes">C:\Users\Ha Nguyen\Desktop</directories>
    <directories realtime="yes" check_all="yes">C:\Users\Ha Nguyen\Documents</directories>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    ```
    Lưu file và chạy `Restart-Service WazuhSvc` trong PowerShell quyền admin để khởi động lại.
- Chạy `cd /var/ossec/etc/shared/default` quyền root để vào folder rồi tạo script với `nano`. Khi tạo xong thì restart lại Wazuh-manager với command `systemctl restart wazuh-manager`:

##### `yara_quick_scan.ps1`:
``` powershell
$LogFile = "C:\Users\Public\yara_debug.log"
function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

$TargetFolders = @()
$Users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($user in $Users) {
    $TargetFolders += "$($user.FullName)\Desktop"
    $TargetFolders += "$($user.FullName)\Documents"
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Starting QUICK SCAN..."

foreach ($Folder in $TargetFolders) {
    if (Test-Path $Folder) {
        # 1. Quét bình thường (Plaintext files)
        $Result = & $YaraExe -w -r $RuleFile "$Folder" 2>&1
        foreach ($line in $Result) {
            if ($line -match "Detect_Sensitive_Info") {
                $FilePath = ($line -split " ")[1]
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
            }
        }

        # 2. DEEP SCAN: Quét xuyên thấu file Microsoft Office (.docx, .xlsx, .pptx)
        $OfficeFiles = Get-ChildItem -Path $Folder -Include *.docx, *.xlsx, *.pptx -Recurse -File -ErrorAction SilentlyContinue
        foreach ($doc in $OfficeFiles) {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"
            
            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                
                # Copy file ra thư mục Temp và ép đổi đuôi thành .zip để PowerShell chịu giải nén
                Copy-Item -Path $doc.FullName -Destination $TempZipPath -Force
                
                # Giải nén từ file .zip
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
                
                # Bắt YARA quét thư mục vừa giải nén
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $($doc.FullName) (Deep Scan Office)"
                        break # Chỉ cần cảnh báo 1 lần cho 1 file Office
                    }
                }
            } catch {
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') DEEP SCAN ERROR: Could not extract $($doc.FullName) - Error: $_"
            } finally {
                # Dọn dẹp sạch sẽ thư mục giải nén và file zip tạm
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: QUICK SCAN completed."
```

##### `yara_full_scan.ps1`:
``` powershell
$LogFile = "C:\Users\Public\yara_debug.log"
function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

$TargetFolders = @()
$Users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($user in $Users) {
    $TargetFolders += "$($user.FullName)\Desktop"
    $TargetFolders += "$($user.FullName)\Documents"
    $TargetFolders += "$($user.FullName)\Music"
    $TargetFolders += "$($user.FullName)\Videos"
    $TargetFolders += "$($user.FullName)\Pictures"
}
$TargetFolders += "C:\Windows\Temp"

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Starting FULL SCAN..."

foreach ($Folder in $TargetFolders) {
    if (Test-Path $Folder) {
        # 1. Quét bình thường (Plaintext files)
        $Result = & $YaraExe -w -r $RuleFile "$Folder" 2>&1
        foreach ($line in $Result) {
            if ($line -match "Detect_Sensitive_Info") {
                $FilePath = ($line -split " ")[1]
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
            }
        }

        # 2. DEEP SCAN: Quét xuyên thấu file Microsoft Office
        $OfficeFiles = Get-ChildItem -Path $Folder -Include *.docx, *.xlsx, *.pptx -Recurse -File -ErrorAction SilentlyContinue
        foreach ($doc in $OfficeFiles) {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"
            
            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -Path $doc.FullName -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
                
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $($doc.FullName) (Deep Scan Office)"
                        break 
                    }
                }
            } catch {
                 Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') DEEP SCAN ERROR: Could not extract $($doc.FullName) - Error: $_"
            } finally {
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: FULL SCAN completed."
```

##### `run_quarantine.ps1`:
``` powershell
$LogFile = "C:\Users\Public\yara_debug.log"
function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: QUARANTINE script started."

try {
    $inputJSON = [Console]::In.ReadLine()
    Write-Log "DEBUG RAW JSON: $inputJSON"

    if ([string]::IsNullOrWhiteSpace($inputJSON)) {
        Write-Log "ERROR: STDIN data is empty."
        exit
    }

    $alert = $inputJSON | ConvertFrom-Json
    $FilePath = $null

    # Uu tien 1: Tu alert.data.file_path (app.py gui qua)
    if ($alert.parameters.alert.data.file_path) {
        $FilePath = $alert.parameters.alert.data.file_path
        Write-Log "DEBUG: Got path from alert.data.file_path -> $FilePath"
    }
    # Uu tien 2: Tu extra_args voi URL decode
    elseif ($alert.parameters.extra_args -and $alert.parameters.extra_args.Count -gt 0) {
        $encoded = $alert.parameters.extra_args[0]
        $FilePath = [System.Uri]::UnescapeDataString($encoded)
        Write-Log "DEBUG: Got path from extra_args (decoded) -> $FilePath"
    }
    # Uu tien 3: Tu syscheck.path
    elseif ($alert.parameters.alert.syscheck.path) {
        $FilePath = $alert.parameters.alert.syscheck.path
        Write-Log "DEBUG: Got path from syscheck -> $FilePath"
    }

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        Write-Log "ERROR: File path is empty after all extraction attempts."
        exit
    }

    Write-Log "DEBUG: Target file path = $FilePath"

    # Resolve case dung (tranh lowercase lam sai duong dan)
    if (Test-Path $FilePath) {
        $FilePath = (Get-Item $FilePath).FullName
        Write-Log "DEBUG: Resolved correct case path: $FilePath"
    }

    $QuarantineDir = "C:\Wazuh_Quarantine"
    if (-not (Test-Path $QuarantineDir)) {
        New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null
        Write-Log "INFO: Created quarantine directory: $QuarantineDir"
    }

    if (Test-Path $FilePath) {
        $FileName = Split-Path $FilePath -Leaf
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $DestPath = "$QuarantineDir\QUARANTINED_${Timestamp}_$FileName"

        Write-Log "DEBUG: Moving file to $DestPath"
        Move-Item -Path $FilePath -Destination $DestPath -Force

        if (Test-Path $DestPath) {
            Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: quarantine_success - File quarantined: $FilePath -> $DestPath"
            # Luu duong dan goc vao .meta de restore sau nay
            $FilePath | Set-Content -Path "$DestPath.meta" -Encoding UTF8 -Force
            Write-Log "DEBUG: Metadata saved to $DestPath.meta"
        } else {
            Write-Log "ERROR: Move-Item failed, file not found in destination."
        }
    } else {
        Write-Log "ERROR: Target file does not exist: $FilePath"
    }

} catch {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Quarantine failed - $_"
}
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/run_quarantine.ps1
sudo chmod 640 /var/ossec/etc/shared/default/run_quarantine.ps1
sudo systemctl restart wazuh-manager
```

##### `restore_quarantine.ps1`:
Chạy lần lượt các command sau:
``` ubuntu
$LogFile       = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"
$QuarantineDir = "C:\Wazuh_Quarantine"
$YaraExe       = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile      = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

function Write-Log {
    param([string]$Msg)
    try {
        $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = New-Object System.IO.StreamWriter($fs)
        $sw.WriteLine($Msg)
        $sw.Close()
        $fs.Close()
    } catch {}
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: RESTORE script started."

# Doc input tu stdin
try {
    $inputJSON = [Console]::In.ReadLine()
    Write-Log "DEBUG RESTORE RAW JSON: $inputJSON"

    if ([string]::IsNullOrWhiteSpace($inputJSON)) {
        Write-Log "ERROR: Empty stdin."
        exit
    }

    $alert = $inputJSON | ConvertFrom-Json
    $SearchName = $null

    if ($alert.parameters.alert.data.file_path) {
        $SearchName = $alert.parameters.alert.data.file_path
        Write-Log "DEBUG: Got search name from data.file_path -> $SearchName"
    }
    elseif ($alert.parameters.extra_args -and $alert.parameters.extra_args.Count -gt 0) {
        $encoded = ($alert.parameters.extra_args -join " ")
        $SearchName = [System.Uri]::UnescapeDataString($encoded)
        Write-Log "DEBUG: Got search name from extra_args (decoded) -> $SearchName"
    }

    if ([string]::IsNullOrWhiteSpace($SearchName)) {
        Write-Log "ERROR: Search name is empty."
        exit
    }

} catch {
    Write-Log "ERROR: Failed to parse JSON - $_"
    exit
}

# Tim file quarantine phu hop
# Ho tro ca ten day du (QUARANTINED_...) lan ten ngan (tm.txt)
$QuarantinedFilePath = $null

if ($SearchName -like "QUARANTINED_*") {
    # Nguoi dung truyen ten day du
    $candidate = Join-Path $QuarantineDir $SearchName
    if (Test-Path $candidate) {
        $QuarantinedFilePath = $candidate
        Write-Log "DEBUG: Found by full name -> $QuarantinedFilePath"
    }
} else {
    # Nguoi dung truyen ten ngan (vi du: tm.txt)
    # Tim trong cac file .meta xem meta nao chua ten file goc tuong ung
    Write-Log "DEBUG: Searching by original filename -> $SearchName"
    $metaFiles = Get-ChildItem -Path $QuarantineDir -Filter "*.meta" -ErrorAction SilentlyContinue
    foreach ($metaFile in $metaFiles) {
        $metaContent = (Get-Content $metaFile.FullName -Encoding UTF8 -Raw).Trim()
        $originalName = Split-Path $metaContent -Leaf
        Write-Log "DEBUG: Checking meta $($metaFile.Name) -> original: $originalName"
        if ($originalName -eq $SearchName) {
            # Lay duong dan file quarantine (bo phan .meta di)
            $QuarantinedFilePath = $metaFile.FullName -replace "\.meta$", ""
            Write-Log "DEBUG: Found match -> $QuarantinedFilePath"
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($QuarantinedFilePath)) {
    Write-Log "ERROR: Cannot find quarantine file matching: $SearchName"
    exit
}

if (-not (Test-Path $QuarantinedFilePath)) {
    Write-Log "ERROR: Quarantined file not found on disk: $QuarantinedFilePath"
    exit
}

$MetaFilePath = "$QuarantinedFilePath.meta"
if (-not (Test-Path $MetaFilePath)) {
    Write-Log "ERROR: Meta file not found: $MetaFilePath"
    exit
}

# Doc duong dan goc tu meta
$OriginalPath = (Get-Content $MetaFilePath -Encoding UTF8 -Raw).Trim()
Write-Log "DEBUG: Original path = $OriginalPath"

if ([string]::IsNullOrWhiteSpace($OriginalPath)) {
    Write-Log "ERROR: Original path in meta file is empty."
    exit
}

# Tao thu muc goc neu chua co
$OriginalDir = Split-Path $OriginalPath -Parent
if (-not (Test-Path $OriginalDir)) {
    New-Item -ItemType Directory -Force -Path $OriginalDir | Out-Null
    Write-Log "INFO: Created directory: $OriginalDir"
}

# Move file ve vi tri goc
try {
    Move-Item -Path $QuarantinedFilePath -Destination $OriginalPath -Force
    Write-Log "INFO: File moved back to: $OriginalPath"
} catch {
    Write-Log "ERROR: Failed to move file - $_"
    exit
}

# Xoa meta file
Remove-Item -Path $MetaFilePath -Force -ErrorAction SilentlyContinue
Write-Log "INFO: Meta file deleted."

# YARA scan lai file vua restore
if (-not (Test-Path $YaraExe)) {
    Write-Log "WARNING: YARA exe not found. File restored but blacklist NOT updated."
    exit
}

Write-Log "INFO: Running YARA scan on restored file..."
$Result = & $YaraExe -w $RuleFile "$OriginalPath" 2>&1
Write-Log "DEBUG YARA output: $Result"

if ($Result -match "Detect_Sensitive_Info") {
    Write-Log "INFO: File still sensitive. Re-adding to blacklist..."
    $currentList = @()
    if (Test-Path $BlacklistFile) {
        $currentList = Get-Content $BlacklistFile
    }
    if ($currentList -notcontains $OriginalPath) {
        Add-Content -Path $BlacklistFile -Value $OriginalPath -Force
    }
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: restore_blacklisted - Restored and re-added to blacklist: $OriginalPath"
    $msgText = "[WAZUH DLP] WARNING: File restored but STILL contains sensitive data. Screenshot protection is ACTIVE."
    Start-Process "msg.exe" -ArgumentList "*", """$msgText""" -NoNewWindow
} else {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: restore_clean - File restored and CLEAN: $OriginalPath"
    $msgText = "[WAZUH DLP] INFO: File restored successfully. Content is clean."
    Start-Process "msg.exe" -ArgumentList "*", """$msgText""" -NoNewWindow
}
```
``` ubuntu
chown wazuh:wazuh /var/ossec/etc/shared/default/restore_quarantine.ps1
chmod 640 /var/ossec/etc/shared/default/restore_quarantine.ps1
```

##### `sensitive_data.yar`:
- Tạo `sensitive_data.yar` bằng cách `sudo -i` rồi chạy lần lượt các command sau:
    ``` ubuntu
    nano /var/ossec/etc/shared/default/sensitive_data.yar
    ```
    ``` yar
    rule Detect_Sensitive_Info {
        meta:
            description = "Phat hien du lieu mat"
        strings:
            $s1 = "password" nocase ascii wide
            $s2 = "hop dong" nocase ascii wide
            $s3 = "mat khau" nocase ascii wide
            $s4 = "báo cáo tài chính" nocase ascii wide
        condition:
            any of them
    }
    ```
    ``` ubuntu
    chown wazuh:wazuh /var/ossec/etc/shared/default/sensitive_data.yar
    chmod 640 /var/ossec/etc/shared/default/sensitive_data.yar
    systemctl restart wazuh-manager
    ```
- Kiểm tra trong `C:\Program Files (x86)\ossec-agent\shared\` trên Windows Agent:
![image](https://hackmd.io/_uploads/rJIUrhDi-g.png)

#### b) Tạo web dashboard:
##### Tạo giao diện web:
- Trên Linux Server, chạy lần lượt command sau để cài Nginx (cài xong nó tự động chạy ngầm ở port `80`):
``` ubuntu
sudo apt update
sudo apt install nginx -y
```
- Chạy lần lượt command sau để xóa trang mặc định của Nginx, tạo file giao diện mới:
``` ubuntu
sudo rm /var/www/html/index.nginx-debian.html
sudo nano /var/www/html/index.html
```
``` html
<!DOCTYPE html>
<html lang="en">
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
                <div class="text-sm">192.168.171.132</div>
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
                document.getElementById('logsBody').innerHTML = `
                    <tr><td colspan="5" class="text-center py-8 text-red-500">
                        [!] CONNECTION ERROR: Unable to fetch data from Middleware.<br>
                        Details: ${error.message}
                    </td></tr>`;
            }
        }

        function filterLogs() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            
            // Lọc dữ liệu qua 2 màng lọc: Search Text và Tab Hiện Tại
            const displayLogs = allLogsData.filter(log => {
                const ruleDesc = log.rule || '';
                const target = log.target || '';
                
                // 1. Màng lọc Search
                const textMatch = `${ruleDesc} ${target}`.toLowerCase().includes(searchTerm);
                
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
                let timestamp = log.time || 'N/A';
                let filePath = log.target || 'N/A';
                let ruleName = log.rule || 'Unknown Rule';
                let severityLevel = log.level || 0;
                
                let severityHtml = `<span class="text-[#00ff41]">${severityLevel}</span>`;
                if (severityLevel >= 12) severityHtml = `<span class="red-glow font-bold text-lg">${severityLevel}</span>`;
                
                // KIỂM TRA TRẠNG THÁI CÁCH LY
                const isQuarantined = quarantinedPaths.has(filePath);
                let actionHtml = '';
                
                if (isQuarantined) {
                    // Tạo tên file quarantine từ đường dẫn gốc để gọi restore
                    const fileName = filePath.split('\\').pop();
                    const quarantineName = quarantinedFileMap[filePath] || '';
                    const restoreBtn = quarantineName 
                        ? `<button onclick="restoreFile('${quarantineName.replace(/'/g, "\\'")}')" 
                              class="border border-yellow-400 text-yellow-400 px-2 py-1 text-[10px] font-bold hover:bg-yellow-400 hover:text-black transition ml-1">
                              [ RESTORE ]
                           </button>`
                        : '';
                    // Nếu đã cách ly -> Hiện nút màu xanh lá
                    actionHtml = `<span class="border border-[#00ff41] bg-green-900/30 text-[#00ff41] px-2 py-1 text-xs font-bold shadow-[0_0_5px_#00ff41_inset]">[ SECURED ]</span>`;
                } else if (filePath !== 'N/A' && filePath !== 'Unknown') {
                    // Chưa cách ly -> Hiện nút Đỏ báo động
                    actionHtml = `<button onclick="quarantineFile('${filePath.replace(/\\/g, '\\\\')}')" class="border border-red-500 text-red-500 px-2 py-1 text-xs font-bold hover:bg-red-500 hover:text-white transition shadow-[0_0_5px_red_inset] animate-pulse">[ QUARANTINE ]</button>`;
                } else {
                    actionHtml = `<span class="text-gray-500 text-xs">-</span>`;
                }

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="opacity-80">${timestamp}</td>
                    <td class="font-bold text-sm">${filePath}</td>
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
- Chạy command sau để đảm bảo `.html` vừa tạo có quyền đọc đúng để Nginx có thể phục vụ nó:
``` ubuntu
sudo chmod 644 /var/www/html/index.html
sudo chown www-data:www-data /var/www/html/index.html
```
- Khởi động lại Nginx:
``` ubuntu
sudo systemctl restart nginx
```

##### Set up Middleware:
> Code Python (Flask) đóng vai trò làm Middleware chạy ở port `5000` để kết nối giao diện với Wazuh API.
- Chạy lần lượt command:
``` ubuntu
sudo apt update
sudo apt install python3-pip python3-venv -y
```
- Tạo thư mục riêng chứa Middleware cho gọn:
``` ubuntu
mkdir -p ~/wazuh-middleware
cd ~/wazuh-middleware
```
- Tạo môi trường ảo, kích hoạt:
``` ubuntu
python3 -m venv venv
source venv/bin/activate
```
> Nếu thấy chữ `(venv)` hiện ở đầu dòng lệnh thì môi trường ảo đã được bật.
> ![image](https://hackmd.io/_uploads/HyryDeNsWg.png)
- Cài thư viện ảo cần thiết (đảm bảo vẫn ở trong `venv`), sau đó mở file lên để cấu hình:
``` ubuntu
pip install flask flask-cors requests urllib3
nano app.py
```
``` py
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import urllib3
import json
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

# Tắt cảnh báo bảo mật khi gọi API bằng HTTPS tự ký (Self-signed certificate) của Wazuh
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ==========================================
# CẤU HÌNH KẾT NỐI WAZUH
# ==========================================
WAZUH_API_PORT = 55000
WAZUH_API_USER = "wazuh"
WAZUH_API_PASS = "Pb5PeAgURdmPE+gNlThICtEUbv4zhuuK"

WAZUH_INDEXER_PORT = 9200
WAZUH_INDEXER_USER = "admin"
WAZUH_INDEXER_PASS = "2aCKDq*lFdmkjv.OGWXQOp7muQCG3sbm"

def get_wazuh_token():
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/security/user/authenticate"
    try:
        response = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
        if response.status_code == 200:
            return response.json()['data']['token']
        print(f"Token retrieval error: {response.text}")
        return None
    except Exception as e:
        print(f"Failed to connect to Wazuh API: {e}")
        return None

# ==========================================
# ENDPOINT 1: LỆNH QUÉT TỪ WEB (TRIGGER SCAN)
# ==========================================
@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    data = request.json
    agent_id = data.get('agent_id', '006')
    scan_type = data.get('scan_type', 'quick')

    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Authentication with Wazuh API failed"}), 401

    command_name = "win_yara_quick0" if scan_type == "quick" else "win_yara_full0"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    
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
# ENDPOINT 3: CÁCH LY FILE (QUARANTINE) - NGUYÊN BẢN (KHÔNG MÃ HÓA)
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
        return jsonify({"error": "Authentication with Wazuh API failed"}), 401

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    
    # Truyền trực tiếp đường dẫn gốc (C:\...) không qua mã hóa
    payload = {
        "command": "win_quarantine0",
        "arguments": [file_path]
    }

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        wazuh_response = response.json()
        
        if response.status_code != 200:
            error_msg = wazuh_response.get("message", str(wazuh_response))
            print(f"\n[WAZUH API ERROR] Port 55000 reported an error: {error_msg}\n")
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
# ENDPOINT 2: LẤY DANH SÁCH CẢNH BÁO DLP TỪ INDEXER
# ==========================================
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    url = f"https://192.168.100.205:{WAZUH_INDEXER_PORT}/wazuh-alerts-*/_search"

    query = {
        "size": 50, 
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "term": {
                "rule.id": "100010"
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
                file_path = full_log.split(' in ')[-1] if ' in ' in full_log else "Unknown"

                clean_alerts.append({
                    "id": hit['_id'],
                    "time": source.get('timestamp', '').replace('T', ' ')[:19],
                    "target": file_path,
                    "rule": source.get('rule', {}).get('description', 'DLP Alert'),
                    "level": source.get('rule', {}).get('level', 12),
                    "agent_name": source.get('agent', {}).get('name', 'N/A'),
                    "actionTaken": "Alerted" 
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
    print("Starting Wazuh DLP Middleware API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
```
- Đảm bảo Ubuntu cho phép kết nối port `5000` và `80`:
``` ubuntu
sudo ufw allow 5000/tcp
sudo ufw allow 80/tcp
```
- Trong Terminal (vẫn đang ở trong `venv`) chạy Middleware:
``` ubuntu
python3 app.py
```
> ![image](https://hackmd.io/_uploads/BynjPlVibe.png)
- Kiểm tra các file ở agent đã đồng bộ với server chưa ở `C:\Program Files (x86)\ossec-agent\shared`:
![image](https://hackmd.io/_uploads/BJC6KGNibl.png)

#### c) Tạo file `.bat` thực thi:
Vào thư mục `C:\Program Files (x86)\ossec-agent\active-response\bin`, tạo lần lượt ba file `.bat` tương ứng đã khai báo với Linux Server trỏ về các script trong thư mục `shared` để thực thi.
- `run_quarantine.bat`:
```
@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\shared\run_quarantine.ps1" 
```
- `run_yara_full.bat`:
```
@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\shared\yara_full_scan.ps1"
```
- `run_yara_quick.bat`:
```
@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\shared\yara_quick_scan.ps1"
```
- `run_restore.bat`:
```
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\restore_quarantine.ps1"
```
