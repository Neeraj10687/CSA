import smtplib, requests, json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from notif_config import *

def send_email(subject, body):
    if not ENABLE_EMAIL:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USERNAME
        msg['To'] = ", ".join(EMAIL_TO)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USERNAME, EMAIL_TO, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[Email] Failed: {e}")

def send_telegram(message):
    if not ENABLE_TELEGRAM:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        requests.post(url, data=data)
    except Exception as e:
        print(f"[Telegram] Failed: {e}")

def send_discord(message):
    if not ENABLE_DISCORD:
        return
    try:
        headers = {"Content-Type": "application/json"}
        payload = {"content": message}
        requests.post(DISCORD_WEBHOOK_URL, headers=headers, data=json.dumps(payload))
    except Exception as e:
        print(f"[Discord] Failed: {e}")

def notify(event_type, file_path=None, url=None, hashes=None, vt_result=None):
    threat_flag = False
    if vt_result and "malicious" in vt_result.get("summary", ""):
        threat_flag = True

    msg = f"Event: {event_type}\n"
    if file_path: msg += f"File: {file_path}\n"
    if url: msg += f"URL: {url}\n"
    if hashes: msg += f"SHA256: {hashes.get('sha256')}\n"
    if vt_result: msg += f"VT Result: {vt_result}\n"

    if threat_flag or event_type.startswith("watchdog_file_created"):
        send_email("Cyber Alert: " + event_type, msg)
        send_telegram(msg)
        send_discord(msg)

