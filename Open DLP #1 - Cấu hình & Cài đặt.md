![Hệ thống Open DLP (Wazuh tích hợp)](https://hackmd.io/_uploads/BJErchmobx.jpg)

## I. Cấu hình máy ảo và cài đặt Wazuh:
### 1. Linux Server:
- Cấu hình ở VMWare:
![image](https://hackmd.io/_uploads/H1VShnQs-l.png)
![image](https://hackmd.io/_uploads/B1eXnhQjZe.png)
![image](https://hackmd.io/_uploads/rk1B6nXoWe.png)
- Cấu hình trong máy ảo:
``` ubuntu
ls /etc/netplan/
```
``` ubuntu
sudo nano /etc/netplan/00-installer-config.yaml
```
``` ubuntu
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.205/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1] 
```
> `Ctrl` + `O` >>> `Enter` >>> `Ctrl` + `X` để lưu và thoát `nano`.
``` ubuntu
sudo netplan apply
```
- Chỉnh múi giờ bằng cách chạy lần lượt các command:
    - Kiểm tra múi giờ: `timedatectl`
    ![image](https://hackmd.io/_uploads/H1BKOCRiZg.png)
    - Chuyển múi giờ về Việt Nam: `sudo timedatectl set-timezone Asia/Ho_Chi_Minh`
    - Bật đồng bộ thời gian tự động: `sudo timedatectl set-ntp true`
    - Kiểm tra lại kết quả: `date`
    ![image](https://hackmd.io/_uploads/BJ1QFACiZl.png)
- Kết nối với [Termius](https://termius.com/index.html):
    - Mở Termius trên máy thật.
    - Chuyển sang tab `Hosts` >>> Click `New Host` (hoặc dấu `+`).
    - Điền các thông tin:
        - Address: Địa chỉ IP của Linux Server (ở đây là `192.168.100.205`).
        - Username: Điền user đã tạo cho Linux Server.
        - Password: Điền mật khẩu.
    - Click đúp vào Host vừa tạo để kết nối. Ở lần đầu, Termius hỏi có tin cậy "fingerprint" của server không, chọn `Add and Continue`.

### 2. Windows Agents:
- Cấu hình ở VMWare:
![image](https://hackmd.io/_uploads/HJEf6hmjZg.png)
![image](https://hackmd.io/_uploads/By8manQo-g.png)
- Cấu hình trong máy ảo:
![image](https://hackmd.io/_uploads/r1wR1pmibx.png)
- Check lần lượt với các command trong Command Prompt:
``` cmd
ipconfig
ping 8.8.8.8
ping 192.168.100.205
```

### 3. Ubuntu Agents:
- Cấu hình ở VMWare:
![image](https://hackmd.io/_uploads/rJ8zgpXsWl.png)
![image](https://hackmd.io/_uploads/HyaQeaXibx.png)
- Cấu hình trong máy ảo: Nhấn `Ctrl` + `Alt` + `T`:
``` ubuntu
ls /etc/netplan/
```
``` ubuntu
sudo nano /etc/netplan/01-network-manager-all.yaml
```
``` ubuntu
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.100.154/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```
> `Ctrl` + `O` >>> `Enter` >>> `Ctrl` + `X` để lưu và thoát `nano`.
``` ubuntu
sudo netplan apply
```
- Kiểm tra kết nối bằng cách gõ lần lượt các command:
``` ubuntu
ip a
ping 8.8.8.8
ping 192.168.100.205
```

### 4. Tải Wazuh:
- Chạy lần lượt command sau trên Linux Server:
``` ubuntu
sudo apt update
curl -SL https://packages.wazuh.com/4.3/wazuh-install.sh -o wazuh-install.sh
sudo bash wazuh-install.sh --generate-config-files
vim config.yml
```
![image](https://hackmd.io/_uploads/SJ7K86XoWl.png)
- Chạy lần lượt command sau để khởi động:
``` ubuntu
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --start-cluster
```
- Lấy thông tin account admin sau khi cài:
``` ubuntu
sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O
```
> ![image](https://hackmd.io/_uploads/SkIVJs1hWg.png)
- Kiểm tra hoạt động của Indexer sau khi cài:
``` ubuntu
curl -k -u admin:<password> https://192.168.100.205:9200
```
- Cài Wazuh Server:
``` ubuntu
sudo bash wazuh-install.sh --wazuh-server wazuh-managernodes
```
- Cài Wazuh Dashboard:
``` ubuntu
sudo bash wazuh-install.sh --wazuh-dashboard wazuh-dashboard
```
- Gõ lần lượt command sau để check trạng thái sau khi cài, hiện `active (running)` là ổn.
``` ubuntu
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
```
- Cài agent trên máy ảo Windows:
    - Truy cập `https://<IP Linux Server>/app/wazuh#` rồi đăng nhập bằng tài khoản admin ở trên, sau đó chọn `Deploy new agent` rồi chọn như hình:
    ![image](https://hackmd.io/_uploads/Hy9JipQo-x.png)
    - Copy lần lượt phần `4` và `5` rồi chạy trong Powershell (Administrator).
    - Kiểm tra:
    ![image](https://hackmd.io/_uploads/HkvIsaQs-l.png)
    - Quay lại trang Wazuh:
    ![image](https://hackmd.io/_uploads/SJAOjaXsWe.png)
- Cài agent trên máy ảo Ubuntu:
    - Mở Terminal chạy command: `apt update && apt install curl -y`
    - Đăng nhập tương tự trên Windows, chọn như hình:
    ![image](https://hackmd.io/_uploads/ryAjia7i-g.png)
    - Copy lần lượt phần `4` và `5` rồi chạy trong Terminal với quyền root.
    - Quay lại Wazuh để check agent đã được tạo chưa.

### 5. Cài đặt tính năng FIM
#### a) Mục tiêu và ứng dụng
- **Mục tiêu:** Sử dụng YARA tích hợp với module FIM của Wazuh để tự động check các file được tạo, sửa xem có phải là file dữ liệu nhạy cảm không.
- **Ứng dụng:** Dùng để check xem liệu có:
    - File nhạy cảm có bị lưu sai thư mục không.
    - Attacker có lưu file nhạy cảm ra các thư mục chỉ định để tiện khai thác không.
    - Đảm bảo cho việc cảnh báo đối với dữ liệu nhạy cảm chưa được mã hóa.

#### b) Nguyên lý vận hành:
- Sơ đồ:
[User tạo/sửa file] ➔ [Wazuh FIM] ➔ [Manager (Alert 550/554)] ➔ [Active Response] ➔ [PowerShell Script] ➔ [YARA Scan] ➔ [Ghi Log Local] ➔ [Log Collector] ➔ [Manager (Decoder/Rule)] ➔ [Dashboard Alert (100010)]
- **Giải thích sơ đồ:**
    - **Wazuh Fim:**
        - **Hoạt động:** Module syscheck trên Wazuh Agent liên tục giám sát theo thời gian thực các thư mục nhạy cảm được chỉ định.
        - **Sự kiện:** Khi user tạo mới hoặc chỉnh sửa một file, hệ điều hành sẽ sinh ra một ngắt sự kiện. Wazuh Agent ngay lập tức tính toán lại mã băm (MD5, SHA1, SHA256) và thu thập thông số của tập tin này.
    - **Manager (Alert 550/554) - Truyền tải:** Agent đóng gói dữ liệu gửi về Wazuh Manager. Manager phân tích và sinh ra cảnh báo mặc định: Rule 554 (File added) hoặc Rule 550 (File modified).
    - **Active Response:**
        - **Phân tích điều kiện:** Wazuh Manager liên tục đối chiếu các cảnh báo vừa sinh ra với cấu hình `<active-response>` trong file `ossec.conf`.
        - **Ra lệnh:** Khi nhận thấy Rule 554 hoặc 550 vừa được kích hoạt, Manager xác định lệnh `win_yara_scan00` (tùy theo tên user tự đặt) cần được thực thi.
        - **Đẩy Payload:** Manager gửi một lệnh thực thi điều khiển từ xa thông qua kênh giao tiếp mã hóa (mặc định port `1514`) xuống chính Agent vừa sinh ra sự kiện, kèm theo một chuỗi dữ liệu JSON (Payload) chứa toàn bộ thông tin về tập tin (bao gồm đường dẫn `$FilePath`).
    - **PowerShell Script:**
        - Tạo một file `.bat` hoặc powershell symplink để tự động gọi S trỏ về script YARA Scan để chạy.
        - Trước khi quét, script kiểm tra sự tồn tại của YARA Engine trong thư mục `dependencies/yara`. Nếu không tìm thấy (do cài đặt mới hoặc bị xóa), script tự động tải xuống mã nguồn từ GitHub, giải nén và cấu hình môi trường mà không cần sự can thiệp của admin.
    - **YARA Scan:** Script YARA được tạo trong thư mục chính sẽ có các nhiệm vụ:
        - Kiểm tra xem máy đã có yara sẵn chưa, chưa thì tự động tải để chạy.
        - Nếu có thì kết hợp với tập rule đã được định nghĩa sẵn (`sensitive_data.yar`) để quét nội dung bên trong của tập tin mục tiêu xem có phải file nhạy cảm không.
    - **Ghi log local:**
        - Tự động ghi log vào file chỉ định trên máy.
        - **Xử lý quyền hạn:** Để tránh các lỗi Access Denied khi Wazuh Agent chạy dưới quyền System hoặc User giới hạn, script chuyển hướng ghi log vào thư mục dùng chung của hệ điều hành: `C:\Users\Public\yara_debug.log`.
        - **Chuẩn hóa định dạng:** Script cấu trúc kết quả quét thành một chuỗi log theo định dạng chuẩn Syslog, bắt đầu bằng thời gian hệ thống.
    - **Log Collector:**
        - Hoạt động: Module `<localfile>` trong cấu hình `agent.conf` của Wazuh Agent liên tục theo dõi file `yara_debug.log`.
        - **Đồng bộ:** Ngay khi phát hiện có dòng dữ liệu mới (sự kiện YARA vừa ghi xuống ở Bước 5), Log Collector đọc dòng text này và đẩy về Wazuh Manager theo luồng thu thập log tiêu chuẩn.
    - **Giải mã (Decoding):**
        - Khi luồng log text về tới Manager, bộ máy giải mã nội bộ nhận diện chuỗi ký tự thời gian ở đầu câu. Nó sử dụng bộ giải mã tích hợp sẵn mang tên `windows-date-format` để tách thời gian và chuẩn bị nội dung log thô.
        - **Đối chiếu Luật (Rule Matching):** Engine Rules của Wazuh tiếp tục phân tích nội dung log đã giải mã. Nó đi qua file `local_rules.xml` và gặp Rule ID 100010.
        - **Kích hoạt Cảnh báo:** Rule 100010 thỏa mãn 2 điều kiện cấu hình: Log thuộc nhóm windows-date-format và chứa chuỗi ký tự `<match>wazuh-yara: alert</match>`.
        - **Hiển thị:** Wazuh Manager ngay lập tức sinh ra một cảnh báo mức độ nghiêm trọng cao (Level 12 - High Severity) và hiển thị lên giao diện Threat Hunting của quản trị viên, hoàn tất quy trình phát hiện và phản hồi sự cố thất thoát dữ liệu.

#### c) Cấu hình:
##### Trên Windows Agent
- Truy cập [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):
![image](https://hackmd.io/_uploads/Hy3APFLiWg.png)
- Làm theo hướng dẫn trong link: https://www.youtube.com/watch?v=KBDf4zJEDaY
- Đi đến `C:\Program Files (x86)\ossec-agent` >> `win32ui`:
![image](https://hackmd.io/_uploads/HJvqdYIiWx.png)
- Chạy file rồi chọn `View Config`:
![image](https://hackmd.io/_uploads/BJC2OF8jZg.png)
- Nhấn tổ hợp `Ctrl` + `F` tìm từ khoá `File integrity`, ta sẽ set up các cấu hình cần thiết ở trong chỗ này:
![image](https://hackmd.io/_uploads/S13ZFt8obe.png)
- Tạo script PowerShell `yara_launcher.ps1` để cài YARA và quét file. Chạy lần lượt các command:
``` ubuntu
sudo -i
cd /var/ossec/etc/shared/default
```
``` ps1
# --- CẤU HÌNH LOG  ---
# --- CONFIGURATION (DEFINE ONCE) ---
$LogFile = "C:\Users\Public\yara_debug.log"

# FUNCTION: WRITE LOG BYPASSING FILE LOCKS
function Write-Log {
    param([string]$Message)
    try {
        $fileStream = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $streamWriter = New-Object System.IO.StreamWriter($fileStream)
        $streamWriter.WriteLine($Message)
        $streamWriter.Close()
        $fileStream.Close()
    } catch {
        # Ignore errors to prevent script crash
    }
}

Write-Log "---------------------------------------------------"
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') DEBUG: YARA Launcher Script started! Waiting for input..."

# --- PART 1: READ DATA FROM WAZUH (STDIN) ---
try {
    $inputJSON = [Console]::In.ReadLine()
    Write-Log "DEBUG: JSON Received: $inputJSON"

    if ([string]::IsNullOrWhiteSpace($inputJSON)) {
        Write-Log "ERROR: JSON input from STDIN is empty. Exiting."
        exit
    }

    $alert = $inputJSON | ConvertFrom-Json
    $FilePath = $null
    
    # EXTRACT FILE PATH
    if ($alert.parameters.alert.syscheck.path) {
        $FilePath = $alert.parameters.alert.syscheck.path
    } elseif ($alert.syscheck.path) {
        $FilePath = $alert.syscheck.path
    }

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        Write-Log "ERROR: JSON does not contain a valid file path. Exiting."
        exit
    }
    
    Write-Log "DEBUG: Target File: $FilePath"

} catch {
    Write-Log "ERROR: Failed to read/parse JSON input. $_"
    exit
}

# --- DIRECTORY CONFIGURATION ---
$SharedDir = "C:\Program Files (x86)\ossec-agent\shared"
$RuleFile = "$SharedDir\sensitive_data.yar"
$InstallDir = "C:\Program Files (x86)\ossec-agent\dependencies\yara"
$YaraExe = "$InstallDir\yara64.exe"
$YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip"

# --- AUTO DOWNLOAD YARA ENGINE ---
if (-not (Test-Path $YaraExe)) {
    try {
        Write-Log "INFO: YARA not found at $InstallDir. Downloading..."
        
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        }

        $ZipPath = "$env:TEMP\yara.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $YaraUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath "$env:TEMP\yara_temp" -Force
        
        Copy-Item "$env:TEMP\yara_temp\yara64.exe" -Destination $YaraExe -Force
        
        Remove-Item $ZipPath -Force
        Remove-Item "$env:TEMP\yara_temp" -Recurse -Force
        Write-Log "INFO: YARA installed successfully."
    } catch {
        Write-Log "ERROR: Failed to download/install YARA. $_"
        exit
    }
}

# --- PART 2: SCANNING LOGIC ---
if (Test-Path $FilePath) {
    if (Test-Path $YaraExe) {
        Write-Log "DEBUG: Scanning file..."
        $AlertTriggered = $false
        
        # 1. Normal Scan (Plaintext/Binary)
        $Result = & $YaraExe -w $RuleFile "$FilePath" 2>&1
        Write-Log "DEBUG: YARA Raw Output: $Result"
        
        if ($Result -match "Detect_Sensitive_Info") { 
            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $LogData = "$Timestamp wazuh-yara: alert - Found Sensitive Data in $FilePath"
            Write-Log $LogData
            Write-Log "SUCCESS: Alert generated."
            $AlertTriggered = $true
        }
        
        # 2. Deep Scan (For MS Office Files)
        if (-not $AlertTriggered -and $FilePath -match "\.(docx|xlsx|pptx)$") {
            Write-Log "DEBUG: Activating Deep Scan for Office file..."
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"
            
            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -Path $FilePath -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
                
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Write-Log "$Timestamp wazuh-yara: alert - Found Sensitive Data in $FilePath (Deep Scan Office)"
                        Write-Log "SUCCESS: Alert generated from Deep Scan."
                        $AlertTriggered = $true
                        break 
                    }
                }
            } catch {
                Write-Log "ERROR DEEP SCAN: Cannot extract file $FilePath - $_"
            } finally {
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }

        if (-not $AlertTriggered) {
            Write-Log "INFO: Clean file (No match found)."
        }
    } else {
        Write-Log "ERROR: YARA exe still missing after download attempt."
    }
} else {
    Write-Log "ERROR: Target file not found: $FilePath"
}
```
- Chuẩn bị file rule `sensitive_data.yar` cho script `yara_launcher.ps1`: Ở đây sẽ chỉ tạo rule đơn giản check số điện thoại và keyword nhạy cảm để check xem có chạy được không thôi, sau sẽ mở rộng thêm.
``` yar                  
rule Detect_Sensitive_Info {
    meta:
        description = "Phat hien du lieu nhay cam (SDT VN, Tu khoa Mat)"
        author = "Security Team"
    strings:
        // Regex bắt số điện thoại VN (09xxx, 03xxx, +84xxx)
        $phone_vn = /(03|05|07|08|09|01[2|6|8|9])+([0-9]{8})\b/

        // Từ khóa nhạy cảm (UTF-16 LE cho Windows Notepad/Word)
        $secret_w = "TUYỆT MẬT" wide nocase
        $secret_a = "TUYỆT MẬT" ascii nocase
        $confidential = "CONFIDENTIAL" wide nocase

    condition:
        $phone_vn or $secret_w or $secret_a or $confidential
}
```

##### Trên Ubuntu Agent:
- Cài YARA bằng cách lần lượt chạy các command:
``` ubuntu
sudo apt update
sudo apt install yara -y
yara --version
```
![image](https://hackmd.io/_uploads/SJSmq2x2-l.png)
- Chạy lần lượt các command sau để cấu hình FIM:
``` ubuntu
sudo nano /var/ossec/etc/ossec.conf
```
Tìm phần `<syscheck>` và thêm:
``` conf
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>

  <!-- Thư mục giám sát realtime -->
  <directories realtime="yes" check_all="yes">/home</directories>
  <directories realtime="yes" check_all="yes">/root/Desktop</directories>
  <directories realtime="yes" check_all="yes">/tmp</directories>
</syscheck>
```
![image](https://hackmd.io/_uploads/rkxXsne2Zx.png)
Thêm `localfile` để đọc log YARA:
``` conf
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/wazuh_yara.log</location>
</localfile>

<localfile>
  <location>active-responses.log</location>
  <log_format>syslog</log_format>
</localfile>
```
![image](https://hackmd.io/_uploads/BJt0snl3Ze.png)
``` ubuntu
sudo systemctl restart wazuh-agent
```
- Trên Linux Server, để tạo YARA rule file rồi đồng bộ xuống agent, chạy lần lượt các command:
``` ubuntu
sudo nano /var/ossec/etc/shared/default/sensitive_data.yar
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
        $s5 = "TUYET MAT" nocase ascii wide
        $phone_vn = /(03|05|07|08|09)[0-9]{8}/
    condition:
        any of them
}
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/sensitive_data.yar
sudo chmod 640 /var/ossec/etc/shared/default/sensitive_data.yar
```
- Cấu hình proxy settings trên Ubuntu Agent:
``` ubuntu
export http_proxy=http://192.168.100.205:3128
export https_proxy=http://192.168.100.205:3128
```
> - Thực hiện theo link: https://systemweakness.com/wazuh-file-integrity-monitoring-fim-guide-for-linux-and-windows-c322d175856e
> - Test trên Terminal:
> ``` ubuntu
> sudo tail -f /var/ossec/logs/ossec.log
> sudo mkdir -p /var/www/test_wazuh
> sudo touch /var/www/test_wazuh/attack.sh
> echo "echo 'Hacked'" | sudo tee /var/www/test_wazuh/attack.sh
> sudo chmod 777 /var/www/test_wazuh/attack.sh
> sudo rm /var/www/test_wazuh/attack.sh
> ```
