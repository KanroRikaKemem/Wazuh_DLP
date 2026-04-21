## IV. Data in use:
### 1. Bảo vệ data khỏi việc rò rỉ bằng USB:
> Công cụ: sysmon

#### a) Mục tiêu và ứng dụng:
- Mục tiêu: Xây dựng phân hệ bảo vệ dữ liệu đang di chuyển (Data-in-Motion) nhằm ngăn user dùng nội bộ sao chép, di chuyển data nhạy cảm từ máy tính của tổ chức ra các thiết bị lưu trữ ngoài (USB, ổ cứng di động, thẻ nhớ).
- Ứng dụng: Khác với các giải pháp cấm USB vật lý (vô hiệu hóa cổng USB) làm ảnh hưởng đến hiệu suất làm việc, phân hệ này ngăn chặn data, không ngăn chặn thiết bị.
    - User vẫn có thể cắm USB để sao chép tài liệu học tập, file cá nhân bình thường.
    - Tuy nhiên, khi user cố tình chép file chứa data mật (do hệ thống định nghĩa bằng YARA) ra thiết bị ngoại vi, hệ thống sẽ lập tức phát hiện và tiêu hủy file đó ngay trên USB, đồng thời gửi cảnh báo pop-up về màn hình user và bắn log lên Dashboard của bộ phận Security.

#### b) Nguyên lý vận hành:
##### Sơ đồ:
[Sysmon Kernel Intercept] ➔ [Wazuh Agent Forwarding] ➔ [Manager Rule Matching] ➔ [Active Response Trigger] ➔ [YARA Deep Scan] ➔ [Eradication & Alert]

##### Giải thích sơ đồ:
- **[Sysmon Kernel Intercept]:** Sysmon (chạy ngầm ở tầng Kernel) tóm sống mọi hành vi tạo file (Event ID 11) trên các ổ đĩa ngoại vi (bỏ qua ổ `C:\` và `D:\`).
- **[Wazuh Agent Forwarding]:** Wazuh Agent trên Windows lắng nghe kênh Microsoft-Windows-Sysmon/Operational, bắt toàn bộ log Event 11 và đẩy lên Server theo real time.
- **[Manager Rule Matching]:** Server nhận log, phân tích và so khớp với bộ rules dành riêng cho event USB.
- **[Active Response Trigger]:** Server lập tức kích nổ cơ chế Active Response (SOAR), bắn một gói tin JSON chứa đường dẫn file vừa tạo về lại máy tính Windows và gọi lệnh thực thi script..
- **[YARA Deep Scan]:** Script PowerShell khởi chạy ở chế độ "Silent Ninja". Nó nhận đường dẫn file từ JSON, gọi YARA Engine ra quét (hỗ trợ giải nén và quét sâu các file `.docx,` `.xlsx`). Nếu file an toàn, tiến trình tự hủy trong im lặng.
- **[Eradication & Alert]:** Nếu YARA phát hiện data nhạy cảm, script lập tức thực thi lệnh xóa sổ (Remove-Item -Force) file đó khỏi USB, đồng thời ghi log tiêu hủy thành công báo về Dashboard.

##### Giải thích chi tiết cơ chế vận hành:
Cơ chế bảo vệ USB của hệ thống vận hành theo chuỗi sáu giai đoạn liên tiếp:
- **Giai đoạn 1 - Giám sát tầng nhân hệ điều hành:** 
Sysmon được cấu hình với bộ lọc sự kiện tùy chỉnh để giám sát toàn bộ hành vi tạo tệp tin (Event ID 11 - FileCreate) trên tất cả các ổ đĩa ngoại vi, loại trừ ổ hệ điều hành C:\. Do hoạt động ở tầng nhân, Sysmon thu thập sự kiện trước khi bất kỳ tiến trình người dùng nào có cơ hội can thiệp, đảm bảo độ tin cậy tuyệt đối của dữ liệu giám sát.
- **Giai đoạn 2 - Chuyển tiếp log lên Wazuh Manager:** 
Wazuh Agent được cấu hình để lắng nghe kênh nhật ký Microsoft-Windows-Sysmon/Operational theo định dạng eventchannel. Ngay khi Sysmon ghi nhận Event ID 11 trên ổ đĩa ngoại vi, Agent đóng gói sự kiện và đẩy về Wazuh Manager theo thời gian thực qua cổng 1514.
- **Giai đoạn 3 - Đối chiếu luật và kích hoạt phản ứng:**
Wazuh Manager nhận log, phân tích và đối chiếu với tập luật DLP tùy chỉnh. Luật 100015 được kích hoạt khi phát hiện sự kiện ghi tệp tin lên ổ đĩa không phải C:\, từ nguồn Microsoft-Windows-Sysmon với Event ID 11. Sau khi luật khớp, cơ chế Active Response lập tức gửi gói tin JSON chứa đường dẫn tệp tin vừa ghi (targetFilename) xuống máy trạm tương ứng.
- **Giai đoạn 4 - Quét nội dung tệp tin (YARA Deep Scan):**
Script PowerShell usb_scan_and_kill.ps1 được kích hoạt thông qua tệp trung gian run_usb_scan.bat. Script hoạt động ở chế độ im lặng, nhận đường dẫn tệp tin từ JSON đầu vào và tiến hành quét bằng YARA Engine với bộ quy tắc sensitive_data.yar. Đối với các tệp tin định dạng Microsoft Office (.docx, .xlsx, .pptx), script kích hoạt cơ chế Deep Scan: sao chép tệp ra thư mục tạm, giải nén cấu trúc XML bên trong và quét đệ quy toàn bộ nội dung. Nếu tệp tin được xác định là an toàn, tiến trình tự kết thúc mà không ghi bất kỳ nhật ký nào, tránh gây nhiễu log hệ thống.
- **Giai đoạn 5 - Tiêu hủy và cảnh báo (Eradication & Alert):**
Khi YARA phát hiện nội dung nhạy cảm, mã thực thi lệnh Remove-Item -Force để xóa vĩnh viễn tệp tin khỏi thiết bị USB, đồng thời ghi nhật ký với định dạng chuẩn vào yara_debug.log và gửi thông báo cảnh báo trực tiếp đến màn hình người dùng thông qua msg.exe. Wazuh Log Collector thu thập nhật ký, kích hoạt luật 100016 (phát hiện dữ liệu mật trên USB) và luật 100017 (tiêu hủy thành công), đẩy cảnh báo lên Dashboard và Telegram Bot.
- **Cơ chế Override (phá khóa khẩn cấp):**
Nhóm nghiên cứu tích hợp thêm một cơ chế linh hoạt nhằm tránh chặn nhầm trong tình huống nghiệp vụ hợp lệ: nếu người dùng sao chép cùng một tệp tin ra USB từ năm lần trở lên trong vòng 2 phút, hệ thống ghi nhận đây là hành vi có chủ đích được phê duyệt và tạm thời cho phép thao tác đó đi qua, đồng thời ghi nhật ký sự kiện Override để quản trị viên xem xét sau.


#### d) Cấu hình:
##### Update cấu hình:
- Trên Windows agent, tạo folder `C:\Users\Ha Nguyen\Documents\SysmonRule\`. Ở phần cấu hình đầu tiên ta đã cấu hình theo [link](https://github.com/SwiftOnSecurity/sysmon-config) nên cần copy file `C:\Program Files\SysinternalsSuite\sysmon\sysmon-config-master\sysmonconfig-export.xml` rồi paste vào folder vừa tạo, sau đó đổi tên nó thành `sysmon_dlp.xml`:
![image](https://hackmd.io/_uploads/Hy8TeqUsWg.png)
- Chỉnh file bằng Notepad, tìm keyword `<EventFiltering>` rồi paste đoạn sau vào dưới dòng chứa keyword và lưu lại:
    ``` xml
        <RuleGroup name="DLP_USB_Monitor" groupRelation="or">
          <FileCreate onmatch="exclude">
            <!-- Bỏ qua mọi hành vi tạo file trên ổ C (Hệ điều hành) -->
            <TargetFilename condition="begin with">C:\</TargetFilename>
            <!-- Nếu máy ảo của bạn có ổ D cố định, hãy bỏ comment dòng bên dưới -->
            <!-- <TargetFilename condition="begin with">D:\</TargetFilename> -->
          </FileCreate>
        </RuleGroup>
    ```
    ![image](https://hackmd.io/_uploads/rkozf5UoWl.png)
- Vào PowerShell, gõ lần lượt các command:
    ``` powershell
    cd "C:\Program Files\SysinternalsSuite\sysmon\sysmon-config-master"
    .\sysmon64.exe -c "C:\Users\Ha Nguyen\Documents\SysmonRule\sysmon_dlp.xml"
    ```
    ![image](https://hackmd.io/_uploads/H18gmc8sWx.png)

##### Để Wazuh Agent đọc được kênh log sysmon để gửi lên Server:
- Mở file `C:\Program Files (x86)\ossec-agent\ossec.conf` bằng Notepad, cuộn xuống dưới cùng rồi tìm thẻ đóng `</ossec_config>`, dán đoạn sau trên thẻ đó rồi lưu lại:
    ``` conf
    <!-- DLP FOR USB -->
    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    ```
    ![image](https://hackmd.io/_uploads/rkNSV9UoZg.png)

##### Tạo file `.bat` để trỏ về script `usb_scan_and_kill.ps1`:
- Vào `C:\Program Files (x86)\ossec-agent\active-response\bin\` tạo file `run_usb_scan.bat` với nội dung:
    ``` bat
    @echo off
    powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\usb_scan_and_kill.ps1"
    ```
    ![image](https://hackmd.io/_uploads/Hyw9BqIj-e.png)
##### Thêm rules:
Vào web Wazuh >>> `Management` >>> `Rules`, tìm `local_rules` rồi `Manage rules files` rồi thêm rule sau, sau đó lưu và restart:
``` xml
<!-- (DLP FOR USB) Bắt Event 11 (FileCreate) từ Sysmon, loại trừ ổ C -->
<rule id="100015" level="12">
  <if_group>windows</if_group>
  <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
  <field name="win.system.eventID">^11$</field>
  <field name="win.eventdata.targetFilename" negate="yes">^C:</field>
  <description>DLP ALERT: File written to USB/External drive via Sysmon - $(win.eventdata.targetFilename)</description>
  <group>usb_dlp,sysmon,</group>
</rule>

<!-- Rule 100016: Cảnh báo phát hiện file mật trên USB -->
<rule id="100016" level="12">
  <decoded_as>windows-date-format</decoded_as>
  <match>wazuh-dlp: alert - SENSITIVE DATA DETECTED ON USB</match>
  <description>DLP CRITICAL: Top Secret data exfiltration to USB detected!</description>
  <group>usb_dlp,yara,</group>
</rule>

<!-- Rule 100017: Thông báo tiêu hủy thành công -->
<rule id="100017" level="7">
  <decoded_as>windows-date-format</decoded_as>
  <match>wazuh-dlp: action_success - USB file destroyed</match>
  <description>DLP INFO: The system has automatically destroyed the leaked file on the USB drive.</description>
  <group>usb_dlp,action_success,</group>
</rule>
```
![image](https://hackmd.io/_uploads/H169s98i-l.png)

##### Cấu hình trên Server:
- Cấu hình Active Response bằng cách mở `/var/ossec/etc/ossec.conf`, kéo đến cuối và thêm rule:
    ```
    <!--   USB Detection -->
    <command>
      <name>win_usb_scan</name>
      <executable>run_usb_scan.bat</executable>
    </command>

    <active-response>
      <command>win_usb_scan</command>
      <location>local</location>
      <rules_id>100015</rules_id>
    </active-response>
    ```
    ![image](https://hackmd.io/_uploads/Bk2s25LoWx.png)
- Để tạo script USB Scan trên server để đồng bộ với agent, chạy lần lượt các command:
    ``` ubuntu
    sudo -i
    cd /var/ossec/etc/shared/default/
    nano usb_scan_and_kill.ps1
    ```
    ``` ps1
    $LogFile = "C:\Users\Public\yara_debug.log"
    $CacheFile = "C:\Users\Public\.usb_override_cache.json"

    function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

    try {
        $inputJSON = [Console]::In.ReadLine()
        if ([string]::IsNullOrWhiteSpace($inputJSON)) { exit }
        $alert = $inputJSON | ConvertFrom-Json
    
        # [QUAN TRỌNG]: Sysmon dùng trường targetFilename thay vì objectName
        $FilePath = $alert.parameters.alert.data.win.eventdata.targetFilename
    
        if (-not $FilePath) { $FilePath = $alert.data.win.eventdata.targetFilename }
    
        if ([string]::IsNullOrWhiteSpace($FilePath)) { exit }
    } catch { exit }

    $YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
    $RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

    # --- OVERRIDE CHECK MECHANISM (5 COPIES IN 2 MINUTES) ---
    $IsOverride = $false
    try {
        $CurrentTime = (Get-Date).Ticks
        $CacheData = @{}
    
        if (Test-Path $CacheFile) {
            $RawCache = Get-Content $CacheFile -Raw | ConvertFrom-Json
            foreach ($prop in $RawCache.psobject.properties) { $CacheData[$prop.Name] = $prop.Value }
        }

        $KeysToRemove = @()
        foreach ($key in $CacheData.Keys) {
            if (($CurrentTime - $CacheData[$key].LastTick) -gt 1200000000) { $KeysToRemove += $key }
        }
        foreach ($key in $KeysToRemove) { $CacheData.Remove($key) }

        if ($CacheData.ContainsKey($FilePath)) {
            $CacheData[$FilePath].Count += 1
            $CacheData[$FilePath].LastTick = $CurrentTime
        } else {
            $CacheData[$FilePath] = @{ Count = 1; LastTick = $CurrentTime }
        }

        if ($CacheData[$FilePath].Count -ge 5) {
            $IsOverride = $true
            $CacheData.Remove($FilePath)
        }

        $CacheData | ConvertTo-Json | Set-Content $CacheFile -Force
    } catch { }

    # --- INITIATE FILE SCAN (SILENT MODE) ---
    if (Test-Path $FilePath) {
        $AlertTriggered = $false
    
        $Result = & $YaraExe -w $RuleFile "$FilePath" 2>&1
        if ($Result -match "Detect_Sensitive_Info") { $AlertTriggered = $true }
    
        if (-not $AlertTriggered -and $FilePath -match "\.(docx|xlsx|pptx)$") {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_usb_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_usb_$TempGuid.zip"
        
            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -Path $FilePath -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
            
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") { $AlertTriggered = $true; break }
                }
            } catch {
            } finally {
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    
        # --- DECISION & ACTION (CHỈ LOG KHI CÓ SỰ CỐ) ---
        if ($AlertTriggered) {
            if ($IsOverride) {
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: alert - Emergency override activated. Target Path: [$FilePath] | App: [USB_Copy]"
            
                # Gửi tin nhắn qua msg.exe xuyên Session (ĐÃ DỊCH SANG TIẾNG ANH)
                $msgText = "[WAZUH DLP] OVERRIDE CONFIRMED: Repeated copy attempts detected. Temporarily allowing file copy to USB for working purposes."
                Start-Process "msg.exe" -ArgumentList "*", """$msgText""" -NoNewWindow
            
            } else {
                # Bổ sung chuẩn Target Path: [...] để app.py bắt được đường dẫn lên Dashboard
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: alert - SENSITIVE DATA DETECTED ON USB! Target Path: [$FilePath]"
                Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
            
                if (-not (Test-Path $FilePath)) {
                    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - USB file destroyed. Target Path: [$FilePath]"
                
                    # Gửi tin nhắn qua msg.exe xuyên Session (ĐÃ DỊCH SANG TIẾNG ANH)
                    $msgText = "[WAZUH DLP] SECURITY WARNING: The file you just copied contains SENSITIVE DATA! The system has AUTOMATICALLY DELETED the file from the USB to prevent data leakage."
                    Start-Process "msg.exe" -ArgumentList "*", """$msgText""" -NoNewWindow
                
                } else {
                    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Failed to delete USB file: Target Path: [$FilePath]"
                }
            }
        }
        # KHÔNG CÓ ELSE CHO NHỮNG FILE BÌNH THƯỜNG ĐỂ TRÁNH RÁC LOG
    }
    ```
    ``` ubuntu
    chown wazuh:wazuh usb_scan_and_kill.ps1
    chmod 640 usb_scan_and_kill.ps1
    ```
- Khởi động lại wazuh-manager: `systemctl restart wazuh-manager`
- Kiểm tra trên Windows Agent bằng cách vào `C:\Program Files (x86)\ossec-agent\shared\`:
![image](https://hackmd.io/_uploads/SJ6MWi8ibl.png)

#### d) Demo:
Vì rules Sysmon được cấu hình là loại trừ ổ `C:` nên bất kỳ ổ đĩa nào khác (`D:`, `E:`, `F:`,...) đều sẽ bị Sysmon giám sát và kích hoạt kịch bản DLP.
> *Nếu có USB thì bỏ qua bước này.*
> **Cách tạo USB ảo (Virtual Hard Disk - VHD) trên Windows Agent:**
> - Chuột phải vào `Start` (logo Windows) >>> `Disk Management`. Trên thanh menu, chọn `Action` >>> `Create VHD`:
> ![image](https://hackmd.io/_uploads/rJJB21PiWe.png)
> - Chọn nơi lưu VHD ảo là `C:\Users\Public\VirtualUSB.vhd`, sau đó nhập `Virtual hard disk size` là `100 MB`. Các thông số khác giữ nguyên:
> ![image](https://hackmd.io/_uploads/B1iin1vj-g.png)
> - Một ổ đĩa xuất hiện ở danh sách bên dưới cùng, đang có chữ `Unknown` và `Not Initialized`. Chuột phải vào chữ `Disk 1` >>> `Initialize Disk` >>> `OK`:
> ![image](https://hackmd.io/_uploads/SJ0R3kPobe.png)
> - Ở ô màu đen (`Unallocated`) bên cạnh ổ đĩa, chuột phải và chọn `New Simple Volume...` rồi bấm `Next` liên tục. Ở bước gán ký tự ổ đĩa (`Assign the following drive letter`) để mặc định. Bấm `Next` cho đến khi `Finish`.
> - Mở `This PC` lên, ta đã có ổ đĩa mới toanh là `E:`:
> ![image](https://hackmd.io/_uploads/rJuB61DiWx.png)
- Chạy lần lượt các command sau trong Linux Server:
    ```
    cd ~/wazuh-middleware
    source venv/bin/activate
    python3 app.py
    ```
    ![image](https://hackmd.io/_uploads/SyRBPUrobl.png)
- Ở Desktop trong Windows Agent đã có file cũ là `Origin.txt` chứa dữ liệu nhạy cảm, tạo thêm file `.txt` mới rồi gõ thêm bất kì thứ gì miễn không chứa keywords:
![image](https://hackmd.io/_uploads/BJGoTyDsbl.png)
![image](https://hackmd.io/_uploads/S1pjpyDo-e.png)
- Copy thẳng hai file vào ổ đĩa USB ảo vừa tạo, có thể thấy rằng `Origin.txt` đã bị xoá:
![image](https://hackmd.io/_uploads/ry7aI2vsbx.png)
- Xem trong log và dashboard:
![image](https://hackmd.io/_uploads/SJS8D3PsZg.png)
![image](https://hackmd.io/_uploads/rkPpPnwsWg.png)
> - Sau khi demo xong, để rút USB ảo, vào lại `Disk Management`, chuột phải disk ảo đó và chọn `Detach VHD`, sau đó xóa file `VirtualUSB.vhd` trong ổ `C` đi.
> - Có thể không cần rút vì mỗi lần tắt máy ổ đĩa ảo sẽ tự biến mất, chỉ cần vào lại `C:\Users\Public\VirtualUSB.vhd` để mở.

### 2. Chức năng ngăn chặn chụp ảnh màn hình:
#### a) Mục tiêu và ứng dụng:
- **Mục tiêu:** Xây dựng chương trình `.exe` cho phép ngăn cản các hành vi chụp hình những file dữ liệu nhạy cảm. Sau đó nối chương trình này với Hệ thống DLP.
- **Ứng dụng:** Dùng để check xem user có chụp hình file chứa dữ liệu nhạy cảm không.

#### b) Nguyên lý vận hành:
**- Sơ đồ:**
[ File Event] ➔ [YARA Scan] ➔ [Cập nhật Blacklist] ➔ [ScreenGuard Daemon] ➔ [Windows API Interception] ➔ [Enforcement & Alert]
- **Giải thích sơ đồ:**
    - **File Event - Phát hiện và Định danh (Detection & Identification):**
        - Tác nhân: Wazuh FIM (File Integrity Monitoring) và `yara_launcher.ps1`.
        - Nguyên lý: Khi user tạo mới hoặc chỉnh sửa một file, Wazuh Agent phát hiện và kích hoạt YARA scan nội dung. Nếu phát hiện keywords (khớp rule `sensitive_data.yar`), script PowerShell sẽ tự động lấy full path của file đó và ghi vào `C:\Users\Public\blacklist.txt`.
        - Mục đích: Tạo ra một danh sách động các tài liệu đang vi phạm cần được bảo vệ màn hình ngay lập tức.
    - **Yara Scan:** Dùng tính năng `yara_scan` để quét dữ liệu nhạy cảm từ đó nhập nhật tên file vào blacklist.
    - **Giám sát Ngữ cảnh (ScreenGuard Daemon):**
        - **Tác nhân:** Ứng dụng C++ (`screen_and_clipboard.exe`) chạy ngầm.
        - **Nguyên lý:** Đọc blacklist mỗi 5 giây, Daemon này tự động tải lại file `blacklist.txt`.
        - **Trình trích xuất thông minh:** Tự động bóc tách đường dẫn dài thành tên file (keyword) để làm dữ liệu đối soát.
        - **Quét cửa sổ hệ thống:** Dùng hàm `EnumWindows` kết hợp `IsWindowVisible` và `!IsIconic` để duyệt qua tất cả các cửa sổ đang hiển thị trên màn hình. Nếu title của bất kỳ cửa sổ nào (Word, Notepad, Trình duyệt) chứa từ khóa từ danh sách đen, hệ thống sẽ chuyển sang trạng thái `SHIELD ACTIVATED` (Kích hoạt khiên).
    - **Can thiệp và Ngăn chặn:**
        - **Tác nhân:** Windows Keyboard Hook và Process Watchdog.
        - **Cơ chế chặn phím cứng:** Sử dụng hàm `SetWindowsHookEx` để móc vào tầng thấp của hệ điều hành. Khi phím Print Screen được nhấn, chương trình sẽ nuốt tín hiệu này (`return 1`), khiến Windows không thể chụp ảnh.
        - **Cơ chế diệt tiến trình:** Một luồng Watchdog liên tục săn lùng các tiến trình phần mềm chụp ảnh màn hình (`SnippingTool.exe`, `ScreenClippingHost.exe`). Nếu thấy chúng khởi chạy khi đang có file mật trên màn hình, Daemon sẽ thực thi lệnh `TerminateProcess` để tiêu diệt chúng ngay lập tức.
        - **Cơ chế Phá kính (Break-glass):** Nếu user nhấn `PrtScn` năm lần trong 20 giây, hệ thống sẽ tạm mở khóa trong 60 giây để phục vụ nhu cầu nghiệp vụ khẩn cấp (có ghi log báo động).
    - **Báo cáo và Pháp y (Reporting & Forensics):**
        - **Tác nhân:** Windows Message Box + `yara_debug.log` + Wazuh Dashboard.
        - Nguyên lý: Mỗi khi ngăn chặn thành công, chương trình thực hiện đồng thời ba việc:
            - Hiển thị thông báo System Popup cảnh báo trực tiếp cho user.
            - Ghi log chi tiết (Thời gian, Tên ứng dụng đang dùng, Đường dẫn đầy đủ của file mật bị chụp) vào `yara_debug.log`.
            - Wazuh Manager thu thập log, đối chiếu Rule ID (`100012`, `100013`, `100014`) và hiển thị báo động đỏ trên Dashboard để admin theo dõi.

#### c) Cấu hình:
##### Update `local_rules.xml`:
Chạy lần lượt các command:
``` ubuntu
sudo nano /var/ossec/etc/rules/local_rules.xml
```
``` xml
  <!-- DLP YARA -->
  <rule id="100010" level="10">
    <!-- Accept default Wazuh decoder -->
    <decoded_as>windows-date-format</decoded_as>
    <match>wazuh-yara: alert</match>
    <description>DLP Alert: YARA detected sensitive data in an unauthorized location</description>
    <group>yara,dlp,</group>
  </rule>

  <!-- DLP Screenshot -->
  <!-- Rule 100011: Screenshot Blocked -->
  <rule id="100011" level="12">
    <decoded_as>windows-date-format</decoded_as>
    <match>wazuh-dlp: alert - Screenshot blocked</match>
    <description>DLP Alert: Screen capture attempt containing sensitive data was blocked</description>
    <group>yara,dlp,screen_guard,</group>
  </rule>

  <!-- Rule 100012: Emergency Override Activated -->
  <rule id="100012" level="12">
    <decoded_as>windows-date-format</decoded_as>
    <match>wazuh-dlp: alert - Emergency override</match>
    <description>DLP CRITICAL: User activated an Emergency Override to capture restricted screen content</description>
    <group>yara,dlp,screen_guard,override,</group>
  </rule>
```
![image](https://hackmd.io/_uploads/BJOvnGYjZe.png)

##### Update lại `app.py` để lấy log:
Chạy lần lượt các command:
``` ubuntu
cd ~/wazuh-middleware
source venv/bin/activate
rm app.py
nano app.py
```
``` py
from datetime import datetime, timezone, timedelta
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
WAZUH_INDEXER_PASS = "2aCkDq*lFdmkjv.OGWXQOp7muQCG3sbm"

def to_vn_time(ts_str):
    if not ts_str: return ''
    try:
        VN_TZ = timezone(timedelta(hours=7))
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.astimezone(VN_TZ).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ts_str.replace('T', ' ')[:19]


def get_wazuh_token():
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/security/user/authenticate"
    try:
        response = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
        if response.status_code == 200:
            return response.json()['data']['token']
        print(f"Error fetching token: {response.text}")
        return None
    except Exception as e:
        print(f"Unable to connect to Wazuh API: {e}")
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
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 401

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
        return jsonify({"error": "Failed to authenticate with Wazuh API"}), 401

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    
    encoded_path = urllib.parse.quote(file_path, safe='')

    payload = {
        "command": "win_quarantine0",
        "custom": False,
        "arguments": [encoded_path]
    }

    print(f"[QUARANTINE] Sending to agent={agent_id}, encoded_path={encoded_path}")

    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        wazuh_response = response.json()
        print(f"[QUARANTINE] Agent={agent_id}, Path={file_path}")
        print(f"[WAZUH RESPONSE] {wazuh_response}")
        
        if response.status_code != 200:
            error_msg = wazuh_response.get("message", str(wazuh_response))
            print(f"\n[WAZUH API ERROR] Port 55000 reported an error: {error_msg}\n")
            return jsonify({"error": f"Wazuh rejected the command: {error_msg}"}), response.status_code
            
        # Luu vao registry
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
        "size": 70, 
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"term": {"rule.id": "100010"}}, # YARA Scan Alert
                    {"term": {"rule.id": "100011"}}, # Screenshot Blocked
                    {"term": {"rule.id": "100012"}}, # Emergency Override
                    {"term": {"rule.id": "100020"}},
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
            return jsonify({"error": "Unable to query Indexer", "details": response.text}), response.status_code

        data = response.json()
        clean_alerts = []

        if 'hits' in data and 'hits' in data['hits']:
            for hit in data['hits']['hits']:
                source = hit['_source']
                
                full_log = source.get('full_log', '')
                file_path = "Unknown"

                # LÔ-GIC MỚI: BÓC TÁCH ĐƯỜNG DẪN THÔNG MINH CHO NHIỀU LOẠI LOG
                data_fields = source.get('data', {})
                if data_fields.get('file_path') and data_fields.get('file_path') != 'Unknown_File':
                    file_path = data_fields['file_path']
                
                # 1. Log từ ScreenGuard C++: "Source Path: [C:\...]" hoặc "Target Path: [C:\...]"
                if 'Source Path: [' in full_log:
                    file_path = full_log.split('Source Path: [')[-1].split(']')[0]
                elif 'Target Path: [' in full_log:
                    file_path = full_log.split('Target Path: [')[-1].split(']')[0]
                
                # 2. Log từ YARA Scan PowerShell: "Found Sensitive Data in C:\..."
                elif ' in ' in full_log:
                    file_path = full_log.split(' in ')[-1].strip()
                    
                # Làm sạch đường dẫn (bỏ khoảng trắng và dấu ngoặc thừa)
                file_path = file_path.strip()

                clean_alerts.append({
                    "id": hit['_id'],
                    "time": to_vn_time(source.get('timestamp', '')),
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

##### Tạo `yara_launcher.ps1`:
- Chạy lần lượt các command sau trong Linux Server:
``` ubuntu
sudo -i
cd /var/ossec/etc/shared/default
nano yara_launcher.ps1
```
``` ps1
# --- CẤU HÌNH (ĐỊNH NGHĨA MỘT LẦN) ---
$LogFile = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"

# HÀM: GHI LOG VÀ BỎ QUA KHÓA FILE (FILE LOCKS) TỪ CÁC TIẾN TRÌNH KHÁC
function Write-Log {
    param([string]$Message)
    try {
        $fileStream = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $streamWriter = New-Object System.IO.StreamWriter($fileStream)
        $streamWriter.WriteLine($Message)
        $streamWriter.Close()
        $fileStream.Close()
    } catch { }
}

# HÀM: THÊM ĐƯỜNG DẪN VÀO DANH SÁCH ĐEN
function Add-ToBlacklist {
    param([string]$PathToAdd)
    try {
        $Exists = $false
        if (Test-Path $BlacklistFile) {
            $content = Get-Content $BlacklistFile
            if ($content -contains $PathToAdd) { $Exists = $true }
        }
        if (-not $Exists) {
            Add-Content -Path $BlacklistFile -Value $PathToAdd -Force
            Write-Log "DEBUG: Auto-added to Blacklist -> $PathToAdd"
        }
    } catch { }
}

Write-Log "---------------------------------------------------"
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') DEBUG: YARA Launcher Script started! Waiting for input..."

# --- PHẦN 1: ĐỌC DỮ LIỆU TỪ WAZUH MANAGER GỬI XUỐNG DƯỚI DẠNG STDIN ---
try {
    $inputJSON = [Console]::In.ReadLine()
    Write-Log "DEBUG: JSON Received: $inputJSON"

    if ([string]::IsNullOrWhiteSpace($inputJSON)) { exit }

    $alert = $inputJSON | ConvertFrom-Json
    $FilePath = $null
    
    # Trích xuất đường dẫn file từ JSON của Wazuh (Hỗ trợ nhiều định dạng log)
    if ($alert.parameters.alert.syscheck.path) {
        $FilePath = $alert.parameters.alert.syscheck.path
    } elseif ($alert.syscheck.path) {
        $FilePath = $alert.syscheck.path
    }

    if ([string]::IsNullOrWhiteSpace($FilePath)) { exit }

} catch { exit }

# --- CẤU HÌNH ĐƯỜNG DẪN THƯ MỤC & CÔNG CỤ ---
$SharedDir = "C:\Program Files (x86)\ossec-agent\shared"
$RuleFile = "$SharedDir\sensitive_data.yar"
$InstallDir = "C:\Program Files (x86)\ossec-agent\dependencies\yara"
$YaraExe = "$InstallDir\yara64.exe"
$YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip"

# --- TỰ ĐỘNG TẢI XUỐNG YARA ENGINE NẾU CHƯA CÓ ---
if (-not (Test-Path $YaraExe)) {
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
        $ZipPath = "$env:TEMP\yara.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $YaraUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath "$env:TEMP\yara_temp" -Force
        Copy-Item "$env:TEMP\yara_temp\yara64.exe" -Destination $YaraExe -Force
        Remove-Item $ZipPath -Force
        Remove-Item "$env:TEMP\yara_temp" -Recurse -Force
    } catch { exit }
}

# --- PHẦN 2: LOGIC QUÉT YARA ---
if (Test-Path $FilePath) {
    if (Test-Path $YaraExe) {
        $AlertTriggered = $false
        
        # 1. Quét thông thường (Cho các file Text, Log, Code, v.v.)
        $Result = & $YaraExe -w $RuleFile "$FilePath" 2>&1
        
        if ($Result -match "Detect_Sensitive_Info") { 
            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Log "$Timestamp wazuh-yara: alert - Found Sensitive Data in $FilePath"
            Add-ToBlacklist -PathToAdd $FilePath
            $AlertTriggered = $true
        }
        
        # 2. Quét sâu (Dành riêng cho nhóm file MS Office: Word, Excel, PowerPoint)
        if (-not $AlertTriggered -and $FilePath -match "\.(docx|xlsx|pptx)$") {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"
            
            try {
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -Path $FilePath -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
                
                # Quét đệ quy toàn bộ các file XML đã giải nén bên trong
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Write-Log "$Timestamp wazuh-yara: alert - Found Sensitive Data in $FilePath (Deep Scan Office)"
                        Add-ToBlacklist -PathToAdd $FilePath
                        $AlertTriggered = $true
                        break 
                    }
                }
            } catch {
            } finally {
                # Dọn dẹp rác (Rất quan trọng để không làm đầy ổ cứng)
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
```
``` ubuntu
sudo nano /var/ossec/etc/ossec.conf
```
``` conf
<command>
  <name>win_yara_scan</name>
  <executable>run_yara_launcher.bat</executable>
</command>

<active-response>
  <command>win_yara_scan</command>
  <location>local</location>
  <rules_id>554,550</rules_id>
</active-response>
```
``` ubuntu
chown wazuh:wazuh /var/ossec/etc/shared/default/yara_launcher.ps1
chmod 640 /var/ossec/etc/shared/default/yara_launcher.ps1
sudo systemctl restart wazuh-manager
```
- Trong Windows Agent, vào `C:\Program Files (x86)\ossec-agent\active-response\bin\` và tạo file `run_yara_launcher.bat`:
``` bat
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\yara_launcher.ps1"
```

##### Update `yara_quick_scan.ps1`:
Chạy lần lượt các command:
``` ubuntu
rm yara_quick_scan.ps1
nano yara_quick_scan.ps1
```
``` ps1
# --- CẤU HÌNH ĐƯỜNG DẪN ---
$LogFile = "C:\Users\Public\yara_debug.log"
$BlacklistFile = "C:\Users\Public\blacklist.txt"

# Hàm ghi log (được tối ưu để bỏ qua lỗi khóa file nếu có tiến trình khác đang ghi)
function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

# Hàm thêm đường dẫn file vi phạm vào danh sách đen
function Add-ToBlacklist {
    param([string]$PathToAdd)
    try {
        $Exists = $false
        if (Test-Path $BlacklistFile) {
            $content = Get-Content $BlacklistFile
            if ($content -contains $PathToAdd) { $Exists = $true }
        }
        if (-not $Exists) {
            Add-Content -Path $BlacklistFile -Value $PathToAdd -Force
            Write-Log "DEBUG: Auto-added to Blacklist -> $PathToAdd"
        }
    } catch { }
}

# Cấu hình đường dẫn YARA engine và Rule
$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

# Chỉ định thư mục mục tiêu: Lấy Desktop và Documents của tất cả user thực
$TargetFolders = @()
$Users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($user in $Users) {
    $TargetFolders += "$($user.FullName)\Desktop"
    $TargetFolders += "$($user.FullName)\Documents"
}

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Starting QUICK SCAN..."

# Duyệt qua từng thư mục mục tiêu để tiến hành quét
foreach ($Folder in $TargetFolders) {
    if (Test-Path $Folder) {
        
        # 1. Quét bình thường bằng YARA (Cho các file text, log...)
        $Result = & $YaraExe -w -r $RuleFile "$Folder" 2>&1
        foreach ($line in $Result) {
            if ($line -match "Detect_Sensitive_Info") {
                $FilePath = ($line -split " ")[1]
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
                Add-ToBlacklist -PathToAdd $FilePath
            }
        }

        # 2. DEEP SCAN (Quét sâu: Giải nén file MS Office để kiểm tra nội dung)
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
                        Add-ToBlacklist -PathToAdd $doc.FullName
                        break 
                    }
                }
            } catch {
            } finally {
                # Dọn dẹp thư mục tạm để không tốn dung lượng ổ C
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Finished QUICK SCAN."
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/yara_quick_scan.ps1
sudo chmod 640 /var/ossec/etc/shared/default/yara_quick_scan.ps1
```

##### Update `yara_full_scan.ps1`:
Chạy lần lượt các command:
``` ubuntu
rm yara_full_scan.ps1
nano yara_full_scan.ps1
```
``` ps1
# --- Cấu hình tệp nhật ký và các biến môi trường ---
$LogFile = "C:\Users\Public\yara_debug.log"

# Hàm ghi nhật ký: Đảm bảo có thể ghi ngay cả khi tệp đang được mở bởi tiến trình khác
function Write-Log { 
    param([string]$Msg) 
    try { 
        $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); 
        $sw = New-Object System.IO.StreamWriter($fs); 
        $sw.WriteLine($Msg); 
        $sw.Close(); 
        $fs.Close() 
    } catch {} 
}

function Add-ToBlacklist {
    param([string]$PathToAdd)
    try {
        $Exists = $false
        if (Test-Path $BlacklistFile) {
            $content = Get-Content $BlacklistFile
            if ($content -contains $PathToAdd) { $Exists = $true }
        }
        if (-not $Exists) {
            Add-Content -Path $BlacklistFile -Value $PathToAdd -Force
            Write-Log "DEBUG: Auto-added to Blacklist -> $PathToAdd"
        }
    } catch { }
}

# Đường dẫn đến công cụ YARA và tệp luật (rules)
$YaraExe = "C:\Program Files (x86)\ossec-agent\dependencies\yara\yara64.exe"
$RuleFile = "C:\Program Files (x86)\ossec-agent\shared\sensitive_data.yar"

# --- Xác định danh sách các thư mục mục tiêu cần quét ---
$TargetFolders = @()
# Lấy danh sách người dùng thực tế, loại bỏ các tài khoản hệ thống mặc định
$Users = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }
foreach ($user in $Users) {
    $TargetFolders += "$($user.FullName)\Desktop"
    $TargetFolders += "$($user.FullName)\Documents"
    $TargetFolders += "$($user.FullName)\Music"
    $TargetFolders += "$($user.FullName)\Videos"
    $TargetFolders += "$($user.FullName)\Pictures"
}
$TargetFolders += "C:\Windows\Temp"

# Thông báo bắt đầu quét toàn bộ hệ thống
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Starting FULL SCAN..."

foreach ($Folder in $TargetFolders) {
    if (Test-Path $Folder) {
        # 1. Quét bình thường (Các tệp văn bản thô/Plaintext)
        $Result = & $YaraExe -w -r $RuleFile "$Folder" 2>&1
        foreach ($line in $Result) {
            if ($line -match "Detect_Sensitive_Info") {
                $FilePath = ($line -split " ")[1]
                Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $FilePath"
                Add-ToBlacklist -PathToAdd $FilePath
            }
        }

        # 2. DEEP SCAN: Quét sâu vào bên trong các tệp Microsoft Office (docx, xlsx, pptx)
        $OfficeFiles = Get-ChildItem -Path $Folder -Include *.docx, *.xlsx, *.pptx -Recurse -File -ErrorAction SilentlyContinue
        foreach ($doc in $OfficeFiles) {
            $TempGuid = [guid]::NewGuid().ToString()
            $TempExtractPath = "$env:TEMP\wazuh_dlp_$TempGuid"
            $TempZipPath = "$env:TEMP\wazuh_dlp_$TempGuid.zip"
            
            try {
                # Tạo thư mục tạm và chuyển đổi file Office sang định dạng Zip để giải nén
                New-Item -ItemType Directory -Path $TempExtractPath -Force | Out-Null
                Copy-Item -Path $doc.FullName -Destination $TempZipPath -Force
                Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractPath -Force -ErrorAction Stop
                
                # Chạy YARA quét các thành phần XML bên trong file Office đã giải nén
                $DeepResult = & $YaraExe -w -r $RuleFile "$TempExtractPath" 2>&1
                foreach ($dLine in $DeepResult) {
                    if ($dLine -match "Detect_Sensitive_Info") {
                        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-yara: alert - Found Sensitive Data in $($doc.FullName) (Deep Scan Office)"
                        Add-ToBlacklist -PathToAdd $FilePath
                        break 
                    }
                }
            } catch {
                 # Ghi lỗi nếu không thể giải nén hoặc quét sâu
                 Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') DEEP SCAN ERROR: Could not extract $($doc.FullName) - Error: $_"
            } finally {
                # Dọn dẹp các tệp tạm sau khi hoàn tất
                if (Test-Path $TempExtractPath) { Remove-Item -Path $TempExtractPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $TempZipPath) { Remove-Item -Path $TempZipPath -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

# Thông báo kết thúc quá trình quét
Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: FULL SCAN finished."
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/yara_full_scan.ps1
sudo chmod 640 /var/ossec/etc/shared/default/yara_full_scan.ps1
sudo systemctl restart wazuh-manager
```

##### Trên Windows Agent:
Kiểm tra `C:\Program Files (x86)\ossec-agent\shared` xem đầy đủ các file vừa update chưa:
![image](https://hackmd.io/_uploads/BylAZYYiWe.png)

#### d) Demo:
> Có thể chạy `Screenshot_and_Clipboard.exe` quyền admin để theo dõi luồng hoạt động.

Thử cap màn hình file `Origin.txt`:
![image](https://hackmd.io/_uploads/BJg2m75iZg.png)
![image](https://hackmd.io/_uploads/S1BOmmcjZg.png)
