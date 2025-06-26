import smtplib
import time
import re
from datetime import datetime
from email.mime.text import MIMEText
from email.header import Header

ATTACK_IDS = {
    "101000", "101001",      # TCP SYN Scan
    "100060", "100061",      # DOS SYN Flood
    "102000", "102001", "102002", "102003", "102004", "102005",  # SQLi
    "100706",                # RCE Samba
    "109802", "109803"       # SSH Brute Force
}

last_sent_time = {}

def should_send_email(sid, interval=60):
    now = time.time()
    last_time = last_sent_time.get(sid, 0)
    if now - last_time > interval:
        last_sent_time[sid] = now
        return True
    return False

def send_email(sender, recipient, subject, body):
    try:
        message = MIMEText(body, "plain", "utf-8")
        message["Subject"] = Header(subject, "utf-8")
        message["From"] = sender
        message["To"] = recipient

        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(sender, "syjl xkgw jlxk oenx")
            smtp.sendmail(sender, recipient, message.as_string())
            print(f"[{datetime.now()}] ✅ Email sent.")
    except Exception as e:
        print(f"[{datetime.now()}] ❌ Error sending email: {e}")

def parse_log_line(line):
    result = {
        "sid": None, "msg": "Không rõ", "classification": "",
        "priority": "", "src": "", "dst": "", "timestamp": ""
    }

    try:
        # Lấy timestamp
        result["timestamp"] = line.split()[0]

        # Lấy SID
        sid_match = re.search(r'\[\d+:(\d+):\d+\]', line)
        if sid_match:
            result["sid"] = sid_match.group(1)

        # Lấy msg
        msg_match = re.search(r']\s(.+?)\s\[\*\*\]', line)
        if msg_match:
            result["msg"] = msg_match.group(1)

        # Classification
        cls_match = re.search(r'Classification:\s(.+?)\]', line)
        if cls_match:
            result["classification"] = cls_match.group(1)

        # Priority
        prio_match = re.search(r'Priority:\s(\d+)', line)
        if prio_match:
            result["priority"] = prio_match.group(1)

        # IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+) -> (\d+\.\d+\.\d+\.\d+:\d+)', line)
        if ip_match:
            result["src"] = ip_match.group(1)
            result["dst"] = ip_match.group(2)

    except Exception as e:
        print(f"[{datetime.now()}] ❌ Lỗi phân tích log: {e}")

    return result

def follow_log(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                data = parse_log_line(line)
                sid = data["sid"]

                if sid:
                    print(f"[{datetime.now()}] 🔍 Found SID: {sid}")

                    if sid in ATTACK_IDS:
                        print(f"[{datetime.now()}] ⚠ SID {sid} thuộc danh sách cảnh báo")

                        if should_send_email(sid):
                            print(f"[{datetime.now()}] 🚨 Gửi email cảnh báo SID: {sid}")

                            email_body = f"""
🔔 PHÁT HIỆN VÀ NGĂN CHẶN TẤN CÔNG IDPS

📅 Thời gian: {data['timestamp']}
📌 SID: {sid}
🧾 Rule: {data['msg']}
📂 Classification: {data['classification']}
⚠ Priority: {data['priority']}
🌐 Từ: {data['src']}
🎯 Đến: {data['dst']}
"""
                            send_email(
                                "youngnvk@gmail.com",
                                "khaicuon18@gmail.com",
                                f"Cảnh báo IDPS - Tấn công: {data['msg']}",
                                email_body.strip()
                            )
                        else:
                            print(f"[{datetime.now()}] ⏳ Đang giới hạn gửi mail cho SID {sid}")
                else:
                    print(f"[{datetime.now()}] ❌ Không tìm thấy SID trong dòng log.")

    except FileNotFoundError:
        print(f"[{datetime.now()}] ❌ Không tìm thấy file log: {filename}")
    except Exception as e:
        print(f"[{datetime.now()}] ❌ Lỗi đọc log: {e}")

if __name__ == "__main__":
    follow_log("/var/log/suricata/fast.log")
