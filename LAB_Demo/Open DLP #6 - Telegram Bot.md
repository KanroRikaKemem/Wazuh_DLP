## VI. Telegram Bot:
### 1. Mục tiêu và ứng dụng:
- **Mục tiêu:** Xây dựng một Telegram Bot có thể nhận log từ hệ thống DLP từ đó phát ra các log cảnh báo vi phạm thất thoát dữ liệu, ngoài ra còn có thể thông qua Telegram Bot để phản ứng trực tiếp đối với các sự cố nghiêm trọng.
- **Ứng dụng:** Việc tích hợp Telebot vào DLP giúp user hay giám sát viên có thể trực tiếp xử lí tình huống vấn đề khẩn cấp bằng điện thoại mà không cần dùng laptop.

### 2. Cơ chế hoạt động:
- **Sơ đồ:**
[Telebot] ➔ [TELEGRAM API] ➔ [`dlp_bot.py`] ➔ [`app.py`] ➔ [Wazuh API - Port `55000`] ➔ [Windows Wazuh Agent]
- **Giải thích sơ đồ:**
    - **[Telebot]**: Nơi đọc tin báo động từ Luồng 1, thấy nguy hiểm nên gõ lệnh `/isolate` (hoặc bấm nút) gửi vào group chat.
    - **[TELEGRAM API] - (Long Polling):** Lệnh của user được lưu tạm trên Telegram server. Lúc này Telegram không tự động đẩy lệnh về server của user được (vì server đứng sau tường lửa). Thay vào đó, nó dùng cơ chế Long Polling là chờ server của bạn chủ động lên hỏi "Có thư mới không?".
    - **[dlp_bot.py] - (C2 Bot)**: Đây là file code chạy ngầm 24/7 trên server. Cứ mỗi vài giây nó lại hỏi Telegram API: "Có nhắn gì không?". Khi thấy lệnh `/isolate`, nó lập tức tóm lấy và gửi một HTTP POST nội bộ (chạy vòng vèo bên trong server Linux) sang cho cái Middleware.
    - **[`app.py`] (Middleware API - Port `5000`):** Là khâu quan trọng nhất trong Luồng 2. Bản thân `dlp_bot.py` không có quyền ra lệnh cho Wazuh. Lệnh `/isolate` qua tay `app.py` sẽ được nó dịch thành ngôn ngữ API phức tạp. Đồng thời, `app.py` sẽ nhét cái Token xác thực vào trong lệnh đó để chứng minh nó là admin.
    - **[Wazuh API - Port 55000]:** Nhận lệnh từ `app.py`, kiểm tra Token thấy đúng là Admin, nó mở cửa và chuyển lệnh điều khiển đó xuống thẳng cho Wazuh Agent đang nằm trên máy tính Windows.
    - **[Wazuh Agent trên Windows] & Thực thi Script:** Agent nhận được mật lệnh và lập tức kích hoạt file `.bat` hoặc `.ps1` (chứa các lệnh như khóa Firewall, vô hiệu hóa Card mạng) đã giấu sẵn trên máy tính client. Mạng bị cắt và quá trình cách ly hoàn tất.

### 3. Cấu hình:
#### a) Khởi tạo Telegram Bot:
- Lên Telegram chat với @BotFather >>> Gõ `/start` >>> `/newbot` >>> Nhập tên Bot >>> Nhập pass cho bot (phải có chữ `bot` cuối cùng) >> Bot được tạo sẽ có token (phải giữ token):
![image](https://hackmd.io/_uploads/SyqaO8Tj-g.png)
![image](https://hackmd.io/_uploads/rkL0uIps-l.png)
- Sau đó add Bot vừa tạo từ `@BotFather` vào Group SOC và lấy Chat ID của Group.
![image](https://hackmd.io/_uploads/By97KLpoWx.png)

#### b) Tạo file script cho Module Integration:
- Script có chức năng nhận log file `json` mà module integration của Wazuh gửi qua sau đó nó sẽ lọc ID rule phù hợp và trích xuất làm đẹp thông tin cần thiết và gửi lên cho Telegram.
- Chạy lần lượt các command:
``` ubuntu
sudo -i
cd /var/ossec/integrations/
sudo nano custom-telegram
```
``` py
#!/usr/bin/env python3
from datetime import datetime, timezone, timedelta
import sys
import json
import requests

def escape_html(text):
    """Escape HTML special characters to prevent Telegram parse errors"""
    if not text:
        return ""
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

# --- CẤU HÌNH BOT ---
TOKEN = '8696356969:AAFfuAvKfwveIEhnuY-qvifs1r6Qkzng8zQ'
CHAT_ID = 7388763844

# CHỐT CHẶN 1: Danh sách các ID muốn nhận (Bảo vệ 2 lớp cùng với ossec.conf)
TARGET_RULE_IDS = ['100010', '100011', '100012', '100015', '100016', '100017', '100018', '100019', '100020']

try:
    with open(sys.argv[1], 'r') as alert_file:
        alert_json = json.load(alert_file)
except Exception:
    sys.exit(0)

rule = alert_json.get('rule', {})
rule_id = str(rule.get('id', '0'))

# Bỏ qua nếu không nằm trong danh sách cần theo dõi
if rule_id not in TARGET_RULE_IDS:
    sys.exit(0)

level = rule.get('level', 0)
description = rule.get('description', 'N/A')
agent_name = alert_json.get('agent', {}).get('name', 'Wazuh Server')

# Convert UTC → Vietnam UTC+7
VN_TZ = timezone(timedelta(hours=7))
raw_time = alert_json.get('timestamp', 'Unknown')
if raw_time != 'Unknown' and 'T' in raw_time:
    try:
        dt = datetime.fromisoformat(raw_time.replace('Z', '+00:00'))
        dt_vn = dt.astimezone(VN_TZ)
        alert_time = dt_vn.strftime('%Y-%m-%d %H:%M:%S')
    except:
        alert_time = raw_time.split('.')[0].replace('T', ' ')
else:
    alert_time = raw_time

if level >= 12:
    icon = "<b>CRITICAL</b>"
elif level >= 8:
    icon = "<b>WARNING</b>"
else:
    icon = "<b>INFO</b>"

msg = f"<b>WAZUH DLP ALERT</b>\n"
msg += f"───────────────\n"
msg += f"{icon} (Level: {level})\n"
msg += f"<b>Rule ID:</b> <code>{rule_id}</code>\n"
msg += f"<b>Time:</b> <code>{alert_time}</code>\n"
msg += f"<b>Agent:</b> <code>{agent_name}</code>\n"
msg += f"───────────────\n"

# --- BÓC TÁCH ĐƯỜNG DẪN THÔNG MINH CHO DLP (100016 - 100020) ---
file_path = "Unknown"
full_log = alert_json.get('full_log', '')
syscheck = alert_json.get('syscheck')

if syscheck:
    file_path = syscheck.get('path', 'Unknown')
elif 'Target Path: [' in full_log:
    file_path = full_log.split('Target Path: [')[-1].split(']')[0]
elif 'Source Path: [' in full_log:
    file_path = full_log.split('Source Path: [')[-1].split(']')[0]
# [BỔ SUNG DÒNG NÀY ĐỂ BẮT LOG YARA 100010]
elif ' in ' in full_log:
    file_path = full_log.split(' in ')[-1].strip()
# ----------------------------------------
elif alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('targetFilename'):
    file_path = alert_json['data']['win']['eventdata']['targetFilename']
elif alert_json.get('data', {}).get('file_path'):
    file_path = alert_json['data']['file_path']

# In mô tả và đường dẫn
msg += f"<b>Description:</b> {escape_html(description)}\n"

if file_path != "Unknown":
    msg += f"<b>File/Path:</b> <code>{escape_html(file_path)}</code>\n"

# In Network IP nếu có
srcip = alert_json.get('data', {}).get('srcip')
reply_markup = {}
if srcip:
    msg += f"<b>Source IP:</b> <code>{escape_html(srcip)}</code>\n"
    reply_markup = {
        "inline_keyboard": [
            [{"text": "Check VirusTotal", "url": f"https://www.virustotal.com/gui/search/{srcip}"}]
        ]
    }

url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
payload = {
    "chat_id": CHAT_ID,
    "text": msg,
    "parse_mode": "HTML"
}
if reply_markup:
    payload["reply_markup"] = reply_markup

try:
    response = requests.post(url, json=payload, timeout=10)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
```
``` ubuntu
chmod +x /var/ossec/integrations/custom-telegram
chown root:wazuh /var/ossec/integrations/custom-telegram
sudo chmod 750 /var/ossec/integrations/custom-telegram
sudo chown root:wazuh /var/ossec/integrations/custom-telegram
```

#### c) Cấu hình `ossec.conf` cho chức năng telebot và cách ly máy:
Chạy lần lượt các command:
``` ubuntu
sudo nano /var/ossec/etc/ossec.conf
```
``` conf
<!-- Bot Telegram  -->
<integration>
  <name>custom-telegram</name>
  <level>3</level>
  <rule_id>100010,100011,100012,100015,100016,100017,100018,100019,100020</rule_id>
  <alert_format>json</alert_format>
</integration>
  
<!-- Isolate -->
<command>
  <name>win_isolate</name>
  <executable>run_isolate.bat</executable>
</command>

<command>
  <name>win_disable</name>
  <executable>run_disable.bat</executable>
</command>

<active-response>
  <command>win_isolate</command>
  <location>local</location>
</active-response>

<active-response>
  <command>win_disable</command>
  <location>local</location>
</active-response>
```
Đảm bảo nằm trước thẻ đóng `</ossec_config>` cuối file:
``` conf
<command>
  <name>win_isolate</name>
  <executable>isolate_network.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>win_disable</name>
  <executable>disable_machine.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

#### d) Khởi tạo `dlp_bot.py`:
- Script có chức năng chủ động kết nối liên tục ra ngoài Internet hướng tới telebot để xem có bất kì dòng lệnh nào được gửi vào không, nếu có thì gửi request nội bộ đến `app.py` để yêu cầu thực hiện chức năng như block, quanrantine,...
- Chạy lần lượt các command:
``` ubuntu
mkdir -p Documents/OpenDLP/tele_bot
cd Documents/OpenDLP/tele_bot
pip3 install pyTelegramBotAPI requests --break-system-packages
sudo nano dlp_bot.py
```
``` py
import telebot
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOKEN = '8696356969:AAFfuAvKfwveIEhnuY-qvifs1r6Qkzng8zQ'
CHAT_ID = '7388763844'
MIDDLEWARE_URL = "http://192.168.100.205:5000/api"

bot = telebot.TeleBot(TOKEN)

def check_chat(message):
    return str(message.chat.id) == CHAT_ID

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    if not check_chat(message): return
    bot.reply_to(message,
        "WAZUH DLP C2 CONSOLE\n"
        "Status: ONLINE\n\n"
        "Control Commands:\n"
        "1. /quarantine agent_id file_path\n"
        "2. /isolate agent_id\n"
        "3. /disable agent_id\n"
        "4. /restore agent_id quarantine_filename\n"
        "5. /listquarantine agent_id\n\n"
    )

@bot.message_handler(commands=['quarantine'])
def handle_quarantine(message):
    if not check_chat(message): return
    args = message.text.split(' ', 2)
    if len(args) < 3:
        bot.reply_to(message, "Syntax: /quarantine 006 C:\\Users\\Secret.txt")
        return
    agent_id, file_path = args[1], args[2]
    bot.reply_to(message, f"Sending quarantine command for {file_path} on Agent {agent_id}...")
    try:
        res = requests.post(f"{MIDDLEWARE_URL}/quarantine",
            json={"agent_id": agent_id, "file_path": file_path}, timeout=10)
        if res.status_code == 200:
            bot.reply_to(message, f"File quarantined successfully on Agent {agent_id}!")
        else:
            error_msg = res.json().get('message', res.json().get('error', res.text))
            bot.reply_to(message, f"API Error ({res.status_code}): {error_msg}")
    except Exception as e:
        bot.reply_to(message, f"Cannot connect to Middleware: {e}")

@bot.message_handler(commands=['isolate'])
def handle_isolate(message):
    if not check_chat(message): return
    args = message.text.split(' ')
    if len(args) < 2:
        bot.reply_to(message, "Syntax: /isolate 006")
        return
    agent_id = args[1]
    bot.reply_to(message, f"Isolating network for Agent {agent_id}...")
    try:
        res = requests.post(f"{MIDDLEWARE_URL}/isolate",
            json={"agent_id": agent_id}, timeout=10)
        if res.status_code == 200:
            bot.reply_to(message, f"Agent {agent_id} network isolated successfully!")
        else:
            error_msg = res.json().get('message', res.json().get('error', res.text))
            bot.reply_to(message, f"API Error ({res.status_code}): {error_msg}")
    except Exception as e:
        bot.reply_to(message, f"Cannot connect to Middleware: {e}")

@bot.message_handler(commands=['disable'])
def handle_disable(message):
    if not check_chat(message): return
    args = message.text.split(' ')
    if len(args) < 2:
        bot.reply_to(message, "Syntax: /disable 006")
        return
    agent_id = args[1]
    bot.reply_to(message, f"Locking Agent {agent_id}...")
    try:
        res = requests.post(f"{MIDDLEWARE_URL}/disable",
            json={"agent_id": agent_id}, timeout=10)
        if res.status_code == 200:
            bot.reply_to(message, f"Agent {agent_id} locked and logged off successfully!")
        else:
            error_msg = res.json().get('message', res.json().get('error', res.text))
            bot.reply_to(message, f"API Error ({res.status_code}): {error_msg}")
    except Exception as e:
        bot.reply_to(message, f"Cannot connect to Middleware: {e}")

@bot.message_handler(commands=['restore'])
def handle_restore(message):
    if not check_chat(message): return
    args = message.text.split(' ', 2)
    if len(args) < 3:
        bot.reply_to(message, 
            "Syntax: /restore 006 QUARANTINED_20260407_123456_filename.txt\n\n"
            "Tip: Tên file lấy từ thư mục C:\\Wazuh_Quarantine\\ trên agent.")
        return
    agent_id = args[1]
    quarantine_filename = args[2]
    bot.reply_to(message, f"Restoring [{quarantine_filename}] on Agent {agent_id}...")
    try:
        res = requests.post(f"{MIDDLEWARE_URL}/restore",
            json={"agent_id": agent_id, "quarantine_filename": quarantine_filename},
            timeout=10)
        if res.status_code == 200:
            bot.reply_to(message, 
                f"[OK] Restore command sent!\n"
                f"File: {quarantine_filename}\n"
                f"YARA will re-scan and update blacklist automatically.")
        else:
            error_msg = res.json().get('error', res.text)
            bot.reply_to(message, f"Error ({res.status_code}): {error_msg}")
    except Exception as e:
        bot.reply_to(message, f"Cannot connect to Middleware: {e}")

@bot.message_handler(commands=['listquarantine'])
def handle_list_quarantine(message):
    if not check_chat(message): return
    args = message.text.split(' ')
    if len(args) < 2:
        bot.reply_to(message, "Syntax: /listquarantine 006")
        return
    agent_id = args[1]
    bot.reply_to(message, f"Fetching quarantine list for Agent {agent_id}...")
    try:
        res = requests.post(f"{MIDDLEWARE_URL}/list_quarantine",
            json={"agent_id": agent_id}, timeout=10)
        if res.status_code == 200:
            data = res.json()
            files = data.get('files', [])
            if not files:
                bot.reply_to(message, "Quarantine vault is EMPTY.")
            else:
                msg = f"FILES IN QUARANTINE VAULT (Agent {agent_id}):\n\n"
                for i, f in enumerate(files, 1):
                    original_path = f.get('original_path', 'Unknown')
                    original_name = f.get('original_name', 'Unknown')
                    q_time = f.get('quarantine_time', 'Unknown')
                    msg += f"{i}. {original_name}\n"
                    msg += f"   Full path: {original_path}\n"
                    msg += f"   Time: {q_time}\n"
                    msg += f"   Restore: /restore {agent_id} {original_name}\n\n"
                bot.reply_to(message, msg)
        else:
            bot.reply_to(message, f"Error: {res.json().get('error', 'Unknown')}")
    except Exception as e:
        bot.reply_to(message, f"Cannot connect to Middleware: {e}")

print("Starting Wazuh DLP Telegram C2 Bot...")
bot.infinity_polling()
```

#### e) Cải tiến `app.py` (Middleware App):
- Cải tiến để có thể nhận thêm 2 yêu cầu là disable và isolate.
- Chạy lần lượt các command:
``` ubuntu
cd ~/wazuh-middleware
sudo nano app.py
```
- Thêm đoạn sau vào code:
``` py
# ==========================================
# ENDPOINT 4: CÔ LẬP MẠNG (ISOLATE NETWORK)
# ==========================================
@app.route('/api/isolate', methods=['POST'])
def isolate_machine():
    data = request.json
    agent_id = data.get('agent_id', '001')
    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Could not authenticate with Wazuh API"}), 401
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    # Kích hoạt script win_isolate0 (cần cấu hình trong ossec.conf)
    payload = {"command": "win_isolate0", "custom": False, "arguments": []}
    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# ENDPOINT 5: KHÓA MÁY (DISABLE MACHINE)
# ==========================================
@app.route('/api/disable', methods=['POST'])
def disable_machine():
    data = request.json
    agent_id = data.get('agent_id', '006')
    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Could not authenticate with Wazuh API"}), 401
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"https://192.168.100.205:{WAZUH_API_PORT}/active-response?agents_list={agent_id}"
    # Kích hoạt script win_disable0 (cần cấu hình trong ossec.conf)
    payload = {"command": "win_disable0", "custom": False, "arguments": []}
    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

#### f) Tạo script trên disable và isolate trên Agent:
Chạy lần lượt các command:
- `disable_machine.ps1`:
``` ubuntu
sudo nano /var/ossec/etc/shared/default/disable_machine.ps1
```
``` ps1
$LogFile = "C:\Users\Public\yara_debug.log"
function Write-Log { param([string]$Msg) Add-Content -Path $LogFile -Value $Msg -ErrorAction SilentlyContinue }

Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Initiating Session 0 Bypass Lockdown..."

try {
    # 1. Gọi lệnh qwinsta để lấy danh sách toàn bộ các Session trong máy
    $qwinstaPath = "$env:windir\System32\qwinsta.exe"
    if (Test-Path "$env:windir\sysnative\qwinsta.exe") { $qwinstaPath = "$env:windir\sysnative\qwinsta.exe" }
    
    $sessions = &$qwinstaPath 2>&1
    Write-Log "Sessions found: $($sessions -join ' | ')"

    # 2. Quét tìm Session nào đang 'Active' (Đang sáng màn hình)
    foreach ($line in $sessions) {
        if ($line -match "Active") {
            
            # Cắt dòng chữ ra để tìm con số Session ID
            $parts = -split $line
            $sessionId = ""
            foreach ($part in $parts) {
                if ($part -match "^\d+$") {
                    $sessionId = $part
                    break
                }
            }
            
            # 3. Kích hoạt ngắt kết nối nhắm thẳng vào Session ID vừa tìm được
            if ($sessionId -ne "") {
                Write-Log "Found Active Target -> Disconnecting Session ID: $sessionId"
                
                $tsdisconPath = "$env:windir\System32\tsdiscon.exe"
                if (Test-Path "$env:windir\sysnative\tsdiscon.exe") { $tsdisconPath = "$env:windir\sysnative\tsdiscon.exe" }
                
                Start-Process -FilePath $tsdisconPath -ArgumentList $sessionId -Wait -NoNewWindow
                Write-Log "Boom! Session $sessionId disconnected."
            }
        }
    }
    
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - Target neutralized."
} catch {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $_"
}
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/disable_machine.ps1
sudo chmod 640 /var/ossec/etc/shared/default/disable_machine.ps1
```
- `isolate_network.ps1`
``` ubuntu
sudo nano /var/ossec/etc/shared/default/isolate_network.ps1
```
``` ps1
$LogFile = "C:\Users\Public\yara_debug.log"
function Write-Log { param([string]$Msg) try { $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite); $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($Msg); $sw.Close(); $fs.Close() } catch {} }

try {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO: Initiating NETWORK ISOLATION protocol from Server..."
    
    # Tìm tất cả card mạng đang kết nối và Vô hiệu hóa (Ngắt mạng)
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false
    
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') wazuh-dlp: action_success - Network isolated successfully."
    
    # Gửi Pop-up cảnh báo cho người dùng
    $msgText = "[WAZUH DLP] SECURITY BREACH: Phat hien rui ro bao mat nghiem trong! May tinh nay da bi NGAT KET NOI MANG de co lap."
    Start-Process "msg.exe" -ArgumentList "*", """$msgText""" -NoNewWindow
    
} catch {
    Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: Network isolation failed - $_"
}
```
``` ubuntu
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/isolate_network.ps1
sudo chmod 640 /var/ossec/etc/shared/default/isolate_network.ps1
```

#### g) Trên Agent Windows:
Vào `C:\Program Files (x86)\ossec-agent\active-response\bin` và tạo:
- `run_disable.bat`:
``` bat
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\disable_machine.ps1"
```
- `run_isolate.bat`:
``` bat
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\isolate_network.ps1"
```
- `isolate_network.cmd`:
``` cmd
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\isolate_network.ps1"
```
- `disable_machine.cmd`:
``` cmd
@echo off
powershell.exe -ExecutionPolicy ByPass -NoProfile -File "C:\Program Files (x86)\ossec-agent\shared\disable_machine.ps1"
```
![image](https://hackmd.io/_uploads/HyCJIik3Zl.png)

### 4. Demo:
- Chạy command `python3 ~/Documents/OpenDLP/tele_bot/dlp_bot.py` và các file `.py` trước đó:
![image](https://hackmd.io/_uploads/S1AeRwpiWg.png)
- Thử tạo và cap màn hình file nhạy cảm:
![image](https://hackmd.io/_uploads/SygPUy7n-e.png)
![image](https://hackmd.io/_uploads/Hy6dIJmnWg.png)
![image](https://hackmd.io/_uploads/r1XqL1QnZl.png)
![image](https://hackmd.io/_uploads/r1y6Iy7h-e.png)
![image](https://hackmd.io/_uploads/B14n8kX2Wl.png)
- Thử kích hoạt các lệnh incident response cơ bản:
![image](https://hackmd.io/_uploads/BJePyvkmhWg.png)
![image](https://hackmd.io/_uploads/BkwLw1Q3We.png)
![image](https://hackmd.io/_uploads/SkMKv173Wg.png)
Có thể thấy rằng file nhạy cảm đã bị cách ly, thư mục cách ly nằm ở `C:\Wazuh_Quarantine\`:
![image](https://hackmd.io/_uploads/SyejDy73be.png)
- Khôi phục file về vị trí cũ:
![image](https://hackmd.io/_uploads/rJxydym2-e.png)
![image](https://hackmd.io/_uploads/HJUlukQhbx.png)
![image](https://hackmd.io/_uploads/H14Wu173Ze.png)
File tiếp tục được đưa vào danh sách nhạy cảm cần theo dõi.
