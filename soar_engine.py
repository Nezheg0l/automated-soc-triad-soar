import os
import requests
import uvicorn
from fastapi import FastAPI, Request, BackgroundTasks
from dotenv import load_dotenv

# Імпорти LimaCharlie SDK v5
from limacharlie.client import Client
from limacharlie.sdk.organization import Organization
from limacharlie.sdk.sensor import Sensor

load_dotenv()

app = FastAPI(title="Enterprise SOC SOAR Engine")

# Ключі з .env
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
LC_OID = os.getenv("LIMACHARLIE_OID")
LC_KEY = os.getenv("LIMACHARLIE_API_KEY")
DEFAULT_SENSOR_ID = os.getenv("LIMACHARLIE_SENSOR_ID")


def send_telegram(text: str):
    """Кубик 1: Відправка сповіщення у Telegram"""
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}
    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.json()
    except Exception as e:
        print(f"[!] Помилка Telegram: {e}")
        return None


def check_virustotal_ip(ip: str) -> int:
    """Кубик 2: Запит Threat Intel у VirusTotal"""
    if not VT_KEY:
        return 0
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip.strip()}"
    headers = {"x-apikey": VT_KEY.strip()}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0)
    except Exception as e:
        print(f"[!] Помилка VirusTotal: {e}")
    return 0


def isolate_host(sensor_id: str) -> bool:
    """Кубик 3: Ізоляція хоста через EDR SDK"""
    try:
        client = Client(oid=LC_OID.strip(), api_key=LC_KEY.strip())
        org = Organization(client)
        sensor = Sensor(org, sensor_id.strip())
        sensor.isolate()
        print(f"[+] SUCCESS: Host {sensor_id} isolated via EDR!")
        return True
    except Exception as e:
        print(f"[!] Помилка LimaCharlie SDK: {e}")
        return False


def process_incident(event_data: dict):
    """
    Playbook: Логіка автоматичного розслідування інциденту
    """
    sensor_id = event_data.get("sid") or DEFAULT_SENSOR_ID
    ip_to_check = event_data.get("dst_ip", "185.220.101.5")
    event_name = event_data.get("event", "SUSPICIOUS_NETWORK_TRAFFIC")

    print(f"\n[*] 🚨 НОВИЙ ІНЦИДЕНТ: {event_name}")
    print(f"[*] Перевіряємо IP {ip_to_check} у VirusTotal...")

    # 1. Threat Intel Enrichment (виклики узгоджено!)
    vt_detections = check_virustotal_ip(ip_to_check)

    # 2. Прийняття рішення (Verdict Logic)
    is_malicious = vt_detections > 0 or "CRITICAL" in event_name.upper()
    verdict = "🔴 TRUE POSITIVE (CRITICAL THREAT)" if is_malicious else "🟡 SUSPICIOUS ACTIVITY"

    # 3. Автоматична ізоляція (Containment)
    isolation_text = "Не вимагалось"
    if is_malicious and sensor_id:
        print(f"[*] Критична загроза підтверджена! Ізолюємо хост {sensor_id}...")
        if isolate_host(sensor_id):
            isolation_text = "🛡️ **ISOLATED VIA EDR SDK**"
        else:
            isolation_text = "⚠️ Помилка ізоляції"

    # 4. Формування звіту у Telegram
    report = (
        f"🚨 *SOC SOAR AUTOMATION INCIDENT*\n\n"
        f"*Verdict:* {verdict}\n"
        f"*Event:* `{event_name}`\n"
        f"*Target Host (SID):* `{sensor_id}`\n"
        f"*Destination IP:* `{ip_to_check}`\n"
        f"*VirusTotal Detections:* `{vt_detections}`\n"
        f"*Automated Action:* {isolation_text}\n\n"
        f"📌 *MITRE ATT&CK:* T1071 (Application Layer Protocol)"
    )
    send_telegram(report)


@app.post("/webhook/alert")
async def receive_alert(request: Request, bg_tasks: BackgroundTasks):
    """Ендпоінт для прийому алерту від Suricata / Wazuh"""
    payload = await request.json()
    bg_tasks.add_task(process_incident, payload)
    return {"status": "ok", "message": "Incident queued for SOAR playbook"}


if __name__ == "__main__":
    print("=== SOC SOAR ENGINE LAUNCHED (Uvicorn Server) ===")
    uvicorn.run(app, host="0.0.0.0", port=8000)
