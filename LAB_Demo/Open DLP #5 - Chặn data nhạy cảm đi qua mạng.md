## V. Ngăn chặn data nhạy cảm ra khỏi lưu lượng mạng:
### 1. Cấu hình:
#### a) Cấu hình để cài đặt Squid Proxy:
##### Cài đặt Squid Proxy và các dependencies cần thiết:
Chạy lần lượt các command:
``` ubuntu
mkdir -p ~/Documents/OpenDLP
cd ~/Documents/OpenDLP
sudo apt install squid-openssl libnss3-tools python3 python3-pip yara p7zip-full -y
```

##### Tạo môi trường ảo và cài đặt thư viện `pyicap`, `yara-python`, `brotli`, `PyPDF2`:
Chạy lần lượt các command:
``` ubuntu
python3 -m venv venv
source venv/bin/activate
pip3 install pyicap yara-python brotli PyPDF2
deactivate
```
##### Cấu hình bẻ khóa HTTPS cho Squid Proxy:
Vì đa số Web hiện nay là HTTPS nên Squid cần một chứng chỉ (Certificate) riêng để làm "Man-in-the-Middle" giải mã gói tin.
- Tạo thư mục và sinh Root CA Certificate:
``` ubuntu
sudo mkdir -p /etc/squid/ssl_cert
sudo -i
cd /etc/squid/ssl_cert
```
- Tạo Private Key và file chứng chỉ (`.pem`):
``` ubuntu
sudo openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 -extensions v3_ca -keyout myCA.pem -out myCA.pem
```
![image](https://hackmd.io/_uploads/ryvazO9jZe.png)
- Phân quyền cho Squid đọc chứng chỉ:
``` ubuntu
sudo chown proxy:proxy myCA.pem
sudo chmod 400 myCA.pem
```
![image](https://hackmd.io/_uploads/rJzEQucs-e.png)
- Đọc file `myCA.pem` gốc, loại bỏ phần Private Key, và xuất phần chứng chỉ ra định dạng DER (`.cer`) rồi cấp quyền:
``` ubuntu
sudo openssl x509 -in /etc/squid/ssl_cert/myCA.pem -outform DER -out ~/Documents/OpenDLP/myCA.cer
sudo chmod 644 ~/Documents/OpenDLP/myCA.cer
```

##### Khởi tạo database cho SSL:
- Chạy lần lượt các command:
``` ubuntu
sudo mkdir -p /var/lib/squid
sudo rm -rf /var/lib/squid/ssl_db
sudo /usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
sudo chown -R proxy:proxy /var/lib/squid/ssl_db
```
- Sau khi tạo xong, ta được một file `ssl_db` với mục đích để tạo nhiều chứng chỉ SSL giả mạo và lưu vào file đó, khi client vào lại các trang web cũ như Mail, Drive thì Squid chỉ cần check lại trên file `ssl_db` mà không cần phải tạo SSL giả mạo khác:
![image](https://hackmd.io/_uploads/BJotG39s-l.png)
![image](https://hackmd.io/_uploads/B1FLQh9iZe.png)

##### Cấu hình Squid Proxy:
- Mở file cấu hình của Squid bằng `sudo nano /etc/squid/squid.conf` rồi xoá toàn bộ cấu hình cũ rồi thêm cấu hình:
``` conf
# --- 1. Cấu hình mạng LAN (THAY ĐỔI THEO DẢI IP CỦA BẠN) ---
acl localnet src 192.168.0.0/16
acl localnet src 10.0.0.0/8
acl localnet src 192.168.100.0/24

# --- 2. Cấu hình cổng và SSL Bump ---
http_port 3128 ssl-bump cert=/etc/squid/ssl_cert/myCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB

# ACL cho SSL Bump
acl step1 at_step SslBump1
# Khai báo file whitelist
acl whitelist ssl::server_name "/etc/squid/whitelist.txt"
# Lệnh Splice (Bypass SSL Bump) cho các tên miền trong whitelist
ssl_bump splice whitelist

ssl_bump peek step1
ssl_bump bump all

# --- 3. Cấu hình ICAP (Gửi gói tin sang Python quét) ---
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_header X-Authenticated-User

# [CƠ CHẾ MỚI] TẮT PREVIEW VÀ ÉP ĐÓNG KẾT NỐI (TRỊ DỨT ĐIỂM LỖI GIAO THỨC)
icap_preview_enable off
icap_persistent_connections off
icap_service_failure_limit -1

# [FAIL-OPEN] Bypass=1 đảm bảo nếu Python sập, mạng vẫn chạy bình thường
icap_service service_req reqmod_precache bypass=1 icap://127.0.0.1:1344/reqmod
adaptation_access service_req allow all

# --- 4. Tối ưu Mạng & Chống Né Tránh ---
dns_v4_first on
forwarded_for delete
request_header_access Via deny all
request_header_access X-Forwarded-For deny all
pinger_enable off # Tắt module Ping IPv6 để dọn sạch log rác

# --- 5. Cấu hình quyền truy cập ---
http_access allow localnet
http_access deny all
cache deny all
```
- Squid sẽ báo lỗi và không thể khởi động nếu file `/etc/squid/whitelist.txt`. Dù hiện tại chưa cần bypass tên miền nào, ta vẫn phải tạo một file trống:
    ``` ubuntu
    sudo touch /etc/squid/whitelist.txt
    sudo chown proxy:proxy /etc/squid/whitelist.txt
    ```
- Chạy command `sudo squid -k parse` để Squid tự động rà soát xem có lỗi cú pháp nào không.
- Khởi động lại Squid: `sudo systemctl restart squid`
- Kiểm tra trạng thái Squid:
![image](https://hackmd.io/_uploads/rJSSu2cjWe.png)

#### b) Lập trình ICAP Server (Python) & YARA:
##### Tạo file YARA rules:
- Chạy lần lượt các command (lưu ý `kanrorikakemem` là tên user):
``` ubuntu
sudo -i
mkdir -p /home/kanrorikakemem/Documents/OpenDLP/network_dlp/
cd /home/kanrorikakemem/Documents/OpenDLP/network_dlp/
nano sensitive.yar
```
- Tạo thử một file mẫu để test:
``` yar
rule Detect_Sensitive_Data {
    meta:
        description = "Network DLP - Sensitive data detection"
        author = "Ha Nguyen"

    strings:
        // ---- PLAINTEXT ----
        $phone_vn = /(03|05|07|08|09)[0-9]{8}/ ascii wide
        $utf8_1 = "TUYỆT MẬT" ascii wide
        $utf8_2 = "Tuyệt Mật" ascii wide

        // ---- HEX (UTF-8 bytes của "TUYỆT MẬT") ----
        $hex_utf8 = { 54 55 59 E1 BB 87 54 20 4D E1 BA AC 54 }

        // ---- HEX (UTF-16 LE của "TUYỆT MẬT") ----
        $hex_utf16 = { 54 00 55 00 59 00 87 1E 54 00 20 00 4D 00 AD 1E 54 00 }

        // ---- URL ENCODED của "TUYỆT MẬT" ----
        $url_1 = "TUY%E1%BB%87T%20M%E1%BA%ACT" nocase ascii
        $url_2 = "TUY%E1%BB%87T+M%E1%BA%ACT" nocase ascii

        // ---- BASE64 của "TUYỆT MẬT" (UTF-8 encoded) ----
        // bytes: 54 55 59 E1 BB 87 54 20 4D E1 BA AC 54
        // base64: "VFVZR+G7h1QgTe..."
        $b64_tuyet_mat_1 = "VFVZR+G7h1Qg" nocase ascii
        $b64_tuyet_mat_2 = "VFVZR-G7h1Qg" nocase ascii

    condition:
        any of them
}
```

##### Code cấu hình ICAP (Python) & YARA:
Chạy lần lượt các command:
`nano icap_server.py`:
``` py
import collections
import collections.abc
collections.Callable = collections.abc.Callable

import socketserver
from pyicap import BaseICAPRequestHandler
import yara
import json
import datetime
import os
import logging
import gzip
import zlib
import brotli
import io
import re
import base64
import uuid
import shutil
import subprocess
import urllib.parse
import time

try:
    import PyPDF2
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

YARA_RULE_PATH = "/home/kanrorikakemem/Documents/OpenDLP/network_dlp/sensitive.yar"
LOG_FILE = "/var/log/network_dlp.log"
MAX_PAYLOAD_SIZE = 15 * 1024 * 1024

DEBUG_PAYLOAD_DUMP = False 

logging.info("Loading YARA Rules into RAM...")
try:
    compiled_rules = yara.compile(filepath=YARA_RULE_PATH)
    logging.info("YARA Rules loaded successfully!")
except Exception as e:
    logging.error(f"CRITICAL ERROR: Failed to load YARA Rule. Details: {e}")
    exit(1)

log_cache = {}
LOG_COOLDOWN_SECONDS = 10 

def check_is_spam(client_ip, url, action, file_name, rule_matched=""):
    global log_cache
    current_time = time.time()
    
    try:
        domain = urllib.parse.urlparse(url).netloc if url.startswith('http') else url[:50]
    except:
        domain = url[:50]
        
    log_signature = f"{client_ip}_{domain}_{action}_{file_name}_{rule_matched}"
    
    if log_signature in log_cache:
        if current_time - log_cache[log_signature] < LOG_COOLDOWN_SECONDS:
            return True 
            
    log_cache[log_signature] = current_time
    
    if len(log_cache) > 500:
        keys_to_delete = [k for k, v in log_cache.items() if current_time - v > LOG_COOLDOWN_SECONDS]
        for k in keys_to_delete:
            del log_cache[k]
            
    return False

def write_log(client_ip, url, action, rule_matched="", size=0, file_name="Unknown_File"):
    # Final master
    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "module": "network_dlp",
        "dlp_action": action,         # Đảm bảo cột ACTION nhận diện được
        "srcip": client_ip,           # Chuẩn srcip của Wazuh
        "src_ip": client_ip,
        "destination_url": url,
        "url": url,
        "payload_size": size,
        "file_path": file_name,       # Chuẩn cho rule hiện tại
        "targetFilename": file_name,  # Chuẩn cho USB Sysmon
        "path": file_name,            # Chuẩn cho FIM/Syscheck
        "target": file_name,
        "file": file_name,
        "rule_matched": rule_matched
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_data) + "\n")
    except Exception as e:
        pass

def get_filename(headers_dict, payload_bytes, req_url, host_str):
    candidates = []
    host_str_lower = host_str.lower()
    
    if b'events.data.microsoft' in host_str_lower.encode() or b'telemetry' in host_str_lower.encode() or b'analytics' in host_str_lower.encode():
        return "[Browser_Telemetry_Leak]"

    try:
        url_unquoted = urllib.parse.unquote(req_url)
        for param in ['name=', 'filename=', 'title=', 'file=', 'path=']:
            idx = url_unquoted.find(param)
            if idx != -1:
                start_idx = idx + len(param)
                end_idx = url_unquoted.find('&', start_idx)
                if end_idx == -1: end_idx = len(url_unquoted)
                extracted = url_unquoted[start_idx:end_idx].split('/')[-1]
                if 0 < len(extracted) < 100:
                    candidates.append(extracted)
    except: pass

    for k, v in headers_dict.items():
        k_lower = k.lower()
        try:
            decoded_v = v[0].decode('utf-8', 'ignore')
            if b'x-upload-content-name' in k_lower or b'x-file-name' in k_lower or b'x-goog-upload-file-name' in k_lower or b'slug' in k_lower:
                candidates.append(urllib.parse.unquote(decoded_v))
            
            if '{' in decoded_v and '}' in decoded_v:
                try:
                    import json
                    json_str = decoded_v[decoded_v.find('{'):decoded_v.rfind('}')+1]
                    arg_json = json.loads(json_str)
                    for key in ['path', 'name', 'filename', 'title']:
                        if key in arg_json and isinstance(arg_json[key], str):
                            candidates.append(arg_json[key].split('/')[-1])
                except: pass
        except: pass
            
    for match in re.finditer(b'(?:filename|name)="([^"]+)"', payload_bytes[:16384]):
        candidates.append(match.group(1).decode('utf-8', 'ignore').split('\\')[-1].split('/')[-1])
        
    match_utf8 = re.search(b"filename\\*=[Uu][Tt][Ff]-8''([^;\r\n&]+)", payload_bytes[:16384])
    if match_utf8:
        candidates.append(urllib.parse.unquote(match_utf8.group(1).decode('utf-8', 'ignore')))
        
    for json_match in re.finditer(b'"(?:name|title|title\\*|path|file_name|filename)"\\s*:\\s*"([^"]+)"', payload_bytes[:16384]):
        val = urllib.parse.unquote(json_match.group(1).decode('utf-8', 'ignore'))
        if '.' in val or len(val) > 4:
            candidates.append(val.split('/')[-1].split('\\')[-1])
        
    for name in candidates:
        name = name.strip()
        if name and name.lower() not in ['blob', 'unknown_file', 'null', 'undefined', 'document', 'file', 'form-data', 'chunk']:
            if '.' in name and len(name) < 150:
                return name
            elif 3 < len(name) < 50:
                return name
            
    return "Unknown_File"

def decode_advanced_encodings(payload_bytes):
    decoded_data = b""
    scan_target = payload_bytes[:1048576] 
    b64_pattern = re.compile(b'[A-Za-z0-9+/_-]{20,}={0,2}') 
    
    for match in b64_pattern.finditer(scan_target):
        try:
            encoded_str = match.group(0)
            padded = encoded_str + (b'=' * ((4 - len(encoded_str) % 4) % 4))
            decoded = base64.urlsafe_b64decode(padded)
            if len(decoded) > 5: 
                decoded_data += decoded + b"\n"
        except:
            pass
            
    if b'\\u' in scan_target:
        try:
            decoded_unicode = scan_target.decode('unicode_escape').encode('utf-8')
            decoded_data += b"\n---UNICODE_DECODED---\n" + decoded_unicode
        except:
            pass

    return decoded_data

def extract_deep_content(payload_bytes):
    extracted_data = b""
    
    pdf_start = payload_bytes.find(b'%PDF-')
    if pdf_start != -1:
        pdf_end = payload_bytes.rfind(b'%%EOF')
        try:
            pdf_data = payload_bytes[pdf_start:pdf_end+5] if pdf_end != -1 else payload_bytes[pdf_start:]
            pdf_stream = io.BytesIO(pdf_data)
            reader = PyPDF2.PdfReader(pdf_stream)
            text_content = ""
            for page in reader.pages:
                extracted_text = page.extract_text()
                if extracted_text:
                    text_content += extracted_text + "\n"
            extracted_data += text_content.encode('utf-8', errors='ignore')
        except Exception:
            pass

    sandbox_dir = f"/tmp/dlp_sandbox_{uuid.uuid4().hex}"
    os.makedirs(sandbox_dir, exist_ok=True)
    
    try:
        magic_idx = -1
        ext = ""
        
        if b'PK\x03\x04' in payload_bytes:
            magic_idx = payload_bytes.find(b'PK\x03\x04')
            ext = ".zip" 
        elif b'7z\xBC\xAF\x27\x1C' in payload_bytes:
            magic_idx = payload_bytes.find(b'7z\xBC\xAF\x27\x1C')
            ext = ".7z"
        elif b'Rar!\x1A\x07' in payload_bytes:
            magic_idx = payload_bytes.find(b'Rar!\x1A\x07')
            ext = ".rar"

        if magic_idx != -1:
            archive_data = payload_bytes[magic_idx:]
            boundary_idx = archive_data.rfind(b'\r\n--')
            if boundary_idx != -1:
                archive_data = archive_data[:boundary_idx]

            archive_path = os.path.join(sandbox_dir, f"temp_archive{ext}")
            with open(archive_path, "wb") as f:
                f.write(archive_data)
            
            subprocess.run(['7z', 'x', '-y', f'-o{sandbox_dir}', archive_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for root, dirs, files in os.walk(sandbox_dir):
            for file in files:
                if file.startswith("temp_archive"):
                    continue
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "rb") as f:
                        extracted_data += f.read() + b"\n"
                except Exception:
                    pass

    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
            
    return extracted_data

class DLP_ICAP_Handler(BaseICAPRequestHandler):
    
    def log_request(self, code='-', size='-'): pass
    def log_message(self, format, *args): pass

    def reqmod_OPTIONS(self):
        try:
            self.set_icap_response(200)
            self.set_icap_header(b'Methods', b'REQMOD')
            self.set_icap_header(b'Service', b'Wazuh ICAP Server')
            self.set_icap_header(b'Options-TTL', b'3600')
            self.set_icap_header(b'Preview', b'0') 
            self.set_icap_header(b'Connection', b'close')
            self.send_headers(False)
        except Exception:
            pass

    def reqmod_REQMOD(self):
        try:
            self.set_icap_header(b'Connection', b'close')

            if not getattr(self, 'enc_req', None) or len(self.enc_req) < 1:
                return self.no_adaptation_required()

            req_line = self.enc_req[0].decode('utf-8', errors='ignore')
            parts = req_line.split(' ')
            method = parts[0] if len(parts) >= 1 else "UNKNOWN"
            req_url = parts[1] if len(parts) >= 2 else ""
            
            host_str = ""
            is_api = False
            headers_dict = self.enc_req_headers if hasattr(self, 'enc_req_headers') and isinstance(self.enc_req_headers, dict) else {}
            
            if headers_dict:
                if b'host' in headers_dict:
                    host_str = headers_dict[b'host'][0].decode('utf-8', 'ignore')
                for key, values in headers_dict.items():
                    for val in values:
                        v_lower = val.lower()
                        if b'application/json' in v_lower or b'xmlhttprequest' in v_lower or b'cors' in v_lower or b'application/x-www-form-urlencoded' in v_lower:
                            is_api = True

            final_url = req_url
            if host_str:
                if not final_url.startswith("http"): final_url = f"https://{host_str}{req_url}"
            if not final_url or final_url == "/": final_url = f"https://{host_str}/" if host_str else "Unknown_Target"

            # Tự động lấy IP người dùng từ Squid (Yêu cầu bật icap_send_client_ip on trong squid.conf)
            client_ip = self.client_address[0]
            if hasattr(self, 'headers') and 'x-client-ip' in self.headers:
                client_ip = self.headers['x-client-ip'][0]
            elif headers_dict and b'x-forwarded-for' in headers_dict:
                client_ip = headers_dict[b'x-forwarded-for'][0].decode('utf-8', 'ignore').split(',')[0].strip()

            if b'mail.google.com' in final_url.lower().encode():
                is_api = True
            
            if method not in ['POST', 'PUT', 'PATCH']:
                return self.no_adaptation_required()

            final_url_lower = final_url.lower().encode()
            
            hang_endpoints = [
                b'/channel/bind', b'/bind', b'mtalk.google.com', b'/sw.js', 
                b'events.data.microsoft', b'/v1/browser/events', b'generate_204',
                b'play.google.com/log', b'/log/client', b'/touch', b'mail.google.com/sync'
            ]
            if any(kw in final_url_lower for kw in hang_endpoints):
                return self.no_adaptation_required()

            payload = b''
            if getattr(self, 'has_body', False):
                while True:
                    try:
                        chunk = self.read_chunk()
                        if chunk == b'': break
                        if len(payload) < MAX_PAYLOAD_SIZE: payload += chunk
                    except Exception: break

            scan_data = payload
            
            is_file_upload = False
            raw_file_name = get_filename(headers_dict, scan_data, final_url, host_str)
            file_name_detected = raw_file_name
            
            host_str_lower_b = host_str.lower().encode()
            ai_domains = [b'gemini.google', b'chatgpt.com', b'openai.com', b'claude.ai', b'copilot.microsoft', b'generativelanguage', b'poe.com', b'perplexity.ai', b'oaiusercontent.com']
            is_ai_prompt = any(domain in host_str_lower_b for domain in ai_domains)
            
            if raw_file_name == "Unknown_File" or raw_file_name == "[Browser_Telemetry_Leak]":
                if raw_file_name == "[Browser_Telemetry_Leak]":
                    is_file_upload = True
                elif is_ai_prompt:
                    file_name_detected = "[AI_Prompt_or_Attachment]"
                    is_file_upload = True
                elif b'mail.google.com' in host_str_lower_b:
                    file_name_detected = "[Gmail_Email_or_Attachment]"
                    is_file_upload = True
                elif b'%PDF-' in scan_data[:2048]:
                    file_name_detected = "Hidden_File.pdf"
                    is_file_upload = True
                elif b'PK\x03\x04' in scan_data[:2048]:
                    file_name_detected = "Hidden_File.zip_docx_xlsx"
                    is_file_upload = True
                elif b'7z\xBC\xAF\x27\x1C' in scan_data[:2048]:
                    file_name_detected = "Hidden_File.7z"
                    is_file_upload = True
                elif b'Rar!\x1A\x07' in scan_data[:2048]:
                    file_name_detected = "Hidden_File.rar"
                    is_file_upload = True
            else:
                is_file_upload = True
                
            if is_file_upload:
                if not check_is_spam(client_ip, final_url, "Scanning", file_name_detected):
                    logging.warning(f"[SCANNING UPLOAD] [{file_name_detected}] {method} - {final_url[:60]}...")
                
            if len(payload) > 0:
                try:
                    if payload.startswith(b'\x1f\x8b'): scan_data = gzip.decompress(payload)
                    elif payload.startswith(b'\x78\x9c') or payload.startswith(b'\x78\xda'): scan_data = zlib.decompress(payload)
                    else: scan_data = brotli.decompress(payload)
                except Exception: pass

                deep_content_raw = extract_deep_content(scan_data)
                if deep_content_raw:
                    scan_data = scan_data + b"\n---DEEP_SCAN_RAW---\n" + deep_content_raw
                    
                advanced_decoded = decode_advanced_encodings(scan_data)
                if advanced_decoded:
                    scan_data = scan_data + b"\n---DECODED_ADVANCED_BOUNDARY---\n" + advanced_decoded
                    
                    if b'PK\x03\x04' in advanced_decoded or b'%PDF-' in advanced_decoded or b'7z\xBC\xAF\x27\x1C' in advanced_decoded or b'Rar!\x1A\x07' in advanced_decoded:
                        deep_content_b64 = extract_deep_content(advanced_decoded)
                        if deep_content_b64:
                            scan_data = scan_data + b"\n---DEEP_SCAN_B64---\n" + deep_content_b64

            matches = compiled_rules.match(data=scan_data) if len(scan_data) > 0 else []
            matched_rule = matches[0].rule if matches else ""

            if matches:
                if file_name_detected == "Unknown_File":
                    file_name_detected = "Hidden_Data_Chunk.txt"

                if not check_is_spam(client_ip, final_url, "Blocked", file_name_detected, matched_rule):
                    logging.error(f"[BLOCKED] Sensitive data detected [{file_name_detected}]: {final_url[:80]} (Rule: {matched_rule})")
                    write_log(client_ip, final_url, "Blocked", matched_rule, len(payload), file_name_detected)
                
                error_html = b"<html><body><h1 style='color:red; font-family:sans-serif'>WAZUH DLP ALERT</h1><p style='font-size: 18px'>Sensitive data upload has been blocked by the security system!</p></body></html>"
                error_json = b'{"error": {"code": 403, "message": "WAZUH DLP ALERT: Upload Blocked due to sensitive data policy."}}'
                
                resp_payload = error_json if is_api else error_html
                content_type = b'application/json' if is_api else b'text/html'
                
                self.set_icap_response(200)
                self.set_enc_status(b'HTTP/1.1 403 Forbidden')
                self.set_enc_header(b'Content-Type', content_type)
                self.set_enc_header(b'Content-Length', str(len(resp_payload)).encode())
                self.set_icap_header(b'Connection', b'close')
                self.send_headers(True)
                self.send_chunk(resp_payload)
                self.send_chunk(b'')
                return
            else:
                if is_file_upload:
                    if not check_is_spam(client_ip, final_url, "Allowed", file_name_detected):
                        logging.info(f"[SAFE] Allowed file [{file_name_detected}] ({len(payload)} bytes)")
                        write_log(client_ip, final_url, "Allowed", "None", len(payload), file_name_detected)

            self.no_adaptation_required()

        except Exception as e:
            try:
                self.no_adaptation_required()
            except Exception:
                pass

class ThreadingICAPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    def handle_error(self, request, client_address): pass

if __name__ == '__main__':
    os.system(f"sudo touch {LOG_FILE} && sudo chmod 666 {LOG_FILE}")
    ThreadingICAPServer.allow_reuse_address = True
    server = ThreadingICAPServer(('0.0.0.0', 1344), DLP_ICAP_Handler)
    logging.info("Network DLP ICAP Server (Final master) is running on port 1344...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down ICAP Server...")
```

##### Cấu hình để tích hợp với Wazuh:
Để chỉ định Wazuh đọc file log Network DLP, mở `nano /var/ossec/etc/ossec.conf` rồi lướt đến xuống dưới cùng và chèn đoạn sau vào ngay trên dòng `</ossec_config>`:
``` conf
<!-- DLP Network -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/network_dlp.log</location>
  </localfile>
```
![image](https://hackmd.io/_uploads/BkFJkT5iZl.png)

##### Khai báo bộ rules hoàn chỉnh cho Network DLP:
Chạy lần lượt các command:
``` ubuntu
nano /var/ossec/etc/rules/local_rules.xml
```
``` xml
<rule id="100020" level="12">
  <decoded_as>json</decoded_as>
  <field name="module">network_dlp</field>
  <field name="dlp_action">Blocked</field>
  <description>Network DLP: Data leak BLOCKED [$(file_path)] (Matched Rule: $(rule_matched)) from Source IP: $(src_ip) to: $(destination_url)</description>
  <group>pci_dss_11.4,gdpr_IV_35.7.d,hipaa_security_164.312.a.1,dlp_network</group>
</rule>
```
``` ubuntu
sudo systemctl restart wazuh-manager
```

#### c) Ở Windows Agent:
##### Cài đặt chứng chỉ Squid lên client:
- Trong Linux Server, chạy lần lượt các command:
``` ubuntu
cd ~/Documents/OpenDLP/
sudo ufw allow 8000/tcp
python3 -m http.server 8000
```
- Trong Windows Agent, truy cập `http://192.168.100.205:8000` và tải `myCA.cer` về:
![image](https://hackmd.io/_uploads/rJubztisWg.png)
- Nhấn `Win` + `R` để mở hộp thoại Run rồi gõ `certlm.msc`.
- Ở cột bên trái, mở rộng thư mục `Trusted Root Certification Authorities` >>> Chuột phải vào thư mục con `Certificates` >>> `All Tasks` > `Import...`, khi đó cửa sổ `Certificate Import Wizard` hiện lên:
![image](https://hackmd.io/_uploads/SJbiip9obx.png)
- Nhấn `Next` >>> `Browse...` rồi đi đến vị trí vừa lưu file `myCA.cer` (nhớ chọn `All Files (.)`) >>> `Next`.
![image](https://hackmd.io/_uploads/rkI8fKioWg.png)
- Đảm bảo `Place all certificates in the following store` đang được chọn và ô `Certificate store` hiển thị là `Trusted Root Certification Authorities` >>> `Next`:
![image](https://hackmd.io/_uploads/HJa5MYsiWl.png)
- Kiểm tra lại rồi `Finish`:
![image](https://hackmd.io/_uploads/H1eCzKjibl.png)
- Mở Settings trên Windows (`Win` + `I`) >>> `Network & internet` >>> `Proxy`:
![image](https://hackmd.io/_uploads/SkJnmKoiWl.png)
- Tại phần `Manual proxy setup`, nhấn `Set up` rồi bật công tắc `Use a proxy server`, sau đó nhập IP của máy Linux vào Port của Squid (mặc định cấu hình OpenSSL bumping thường là 3128 hoặc cổng đã cấu hình trong `squid.conf`) rồi lưu lại:
![image](https://hackmd.io/_uploads/H1EQNtsjbg.png)
- Mở trang web bất kì, rồi chọn như ảnh sau:
![image](https://hackmd.io/_uploads/rkRkSYsibl.png)
Kiểm tra chứng chỉ:
![image](https://hackmd.io/_uploads/ry0hVYijbx.png)
- Để chặn trên trình duyệt client, mở `edge://flags/` rồi tìm `QUIC`, ta sẽ thấy `Experimental QUIC protocol`:
![image](https://hackmd.io/_uploads/HycnBFss-g.png)
- Đổi trạng thái từ `Default` sang `Disabled` rồi nhấn `Restart` ở góc dưới bên phải để khởi động lại trình duyệt:
![image](https://hackmd.io/_uploads/rJWVUYijbg.png)

### 2. Demo:
#### a) Trong Linux Server:
Chạy lần lượt các command:
``` ubuntu
sudo apt install tmux -y
tmux
cd ~/Documents/OpenDLP/network_dlp
python3 -m venv venv
source venv/bin/activate
pip3 install pyicap yara-python brotli PyPDF2
python3 icap_server.py
```
Nhấn `Ctrl` + `B` rồi nhấn `%`
``` ubuntu
cd ~/wazuh-middleware
source venv/bin/activate
python3 app.py
```
![image](https://hackmd.io/_uploads/r1XF_gni-e.png)

##### Trong Windows Agent:
- Thử vào một trang web bất kì, nếu thành công là được:
![image](https://hackmd.io/_uploads/Sy0dLtss-g.png)
- Nội dung file nhạy cảm `File_TuyetMat.txt`:
![image](https://hackmd.io/_uploads/H1YrOG2sWe.png)
- Thử upload file nhạy cảm và một file bình thường lên ChatGPT thì file nhạy cảm bị chặn:
![image](https://hackmd.io/_uploads/S1NVgosjZe.png)
![image](https://hackmd.io/_uploads/rJ2hdM3jWe.png)
![image](https://hackmd.io/_uploads/rkWEEWajbg.png)
- Thử upload file lên Drive:
![image](https://hackmd.io/_uploads/ByneSZpibe.png)
![image](https://hackmd.io/_uploads/B1h-S-asWg.png)
![image](https://hackmd.io/_uploads/H1sfBbTiWl.png)
- Gửi qua Gmail:
![image](https://hackmd.io/_uploads/HktUrLTsWx.png)
![image](https://hackmd.io/_uploads/HJwwSUTiWg.png)
![image](https://hackmd.io/_uploads/Sk2iS8pjbe.png)
