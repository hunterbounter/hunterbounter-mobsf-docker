import threading

import aiohttp
import psutil
import json
import requests
import time
import subprocess
import logging
from datetime import datetime

from agent.mobsf import MobSF

mobfs = MobSF()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)

# Author : HunterBounter

def send_scan_results(scan_results):
    try:
        response = requests.post('https://panel.hunterbounter.com/scan_results/save', data=scan_results)
        if response.status_code != 200:
            print(f"Failed to send scan results: {response.text}")
    except Exception as e:
        print(f"Failed to send scan results: {e}")


def get_host_name():
    try:
        host_name = subprocess.run(['hostname'], capture_output=True, text=True)
        return host_name.stdout.strip()
    except Exception as e:
        return f"Hata: {e}"


get_host_name()


def get_active_interfaces():
    if_addrs = psutil.net_if_addrs()
    active_interfaces = {interface: addrs[0].address for interface, addrs in if_addrs.items() if addrs}
    return active_interfaces


def get_cpu_serial():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    return line.split(':')[1].strip()

    except Exception as e:
        return str(e)


def convert_bytes_to_gb(bytes_value):
    return bytes_value / (1024 * 1024 * 1024)


def classify_status(value, normal_threshold, medium_threshold):
    if value < normal_threshold:
        return "NORMAL"
    elif value < medium_threshold:
        return "MEDIUM"
    else:
        return "CRITICAL"


def get_uptime():
    uptime_seconds = int(time.time() - psutil.boot_time())
    uptime_days = uptime_seconds // (24 * 60 * 60)
    uptime_seconds %= (24 * 60 * 60)
    uptime_hours = uptime_seconds // (60 * 60)
    uptime_seconds %= (60 * 60)
    uptime_minutes = uptime_seconds // 60
    return f"{uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes"


def get_disk_status(used_percent):
    if used_percent < 70:
        return "NORMAL"
    elif used_percent < 90:
        return "MEDIUM"
    else:
        return "CRITICAL"
def download_file(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.content


def get_server_stats():
    logger.info("get_server_stats - Starting to gather server statistics")

    try:
        # Hostname'i alma ve loglama
        hostname = get_host_name()
        logger.info(f"get_server_stats - Hostname: {hostname}")

        # RAM kullanımını alma ve loglama
        ram_usage = psutil.virtual_memory().percent
        logger.info(f"get_server_stats - RAM Usage: {ram_usage}%")

        # CPU kullanımını alma ve loglama
        cpu_usage = psutil.cpu_percent()
        logger.info(f"get_server_stats - CPU Usage: {cpu_usage}%")

        # Aktif ağ arayüzlerini alma ve loglama
        active_interfaces = get_active_interfaces()
        logger.info(f"get_server_stats - Active Interfaces: {active_interfaces}")

        # Disk kullanımını alma ve loglama
        disk_usage = psutil.disk_usage('/')
        logger.info(f"get_server_stats - Disk Usage: {disk_usage.percent}%")

        # Toplam tarama sayısını alma ve loglama
        total_scan_count = mobfs.active_scans_count()
        logger.info(f"get_server_stats - Total scan count: {total_scan_count}")

        # MobSF durumunu kontrol etme ve loglama
        mobfs_status = mobfs.check_mobfs_is_online()
        if mobfs_status:
            mobfs_status = "online"
            logger.info("get_server_stats - MobSF is online")
        else:
            mobfs_status = "offline"
            logger.warning("get_server_stats - MobSF is offline")

        # Sunucu çalışma süresini alma ve loglama
        uptime = get_uptime()
        logger.info(f"get_server_stats - Server Uptime: {uptime}")

        # Sunucu istatistiklerini bir araya getirme ve loglama
        stats = {
            "hostname": hostname,
            "telemetry_type": "mobfs",
            "active_scan_count": total_scan_count,
            "openvas_status": mobfs_status,
            "active_interfaces": active_interfaces,
            "uptime": uptime,
            "ram_usage": ram_usage,
            "cpu_usage": cpu_usage,
            "active_connections": len(psutil.net_connections()),
            "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        logger.info(f"get_server_stats - Server stats compiled: {stats}")

        # MobSF çevrimiçi ise hedefleri al ve APK'leri işle
        if mobfs_status == "online":
            logger.info("get_server_stats - MobSF is online, attempting to retrieve targets")
            target_response = get_targets(total_scan_count, 4)

            if target_response['success']:
                logger.info(f"get_server_stats - Targets received successfully: {target_response}")

                targets = target_response['data']['targets']

                if targets is not None:
                    for target in targets:
                        logger.info(f"get_server_stats - Downloading APK from {target}")
                        try:
                            file_content = download_file(target)
                            logger.info(f"get_server_stats - Uploading APK to MobSF")
                            upload_response = mobfs.upload_apk(file_content, target.split('/')[-1])
                            logger.info(f"get_server_stats - Scanning APK with MobSF")
                            #scan_response = mobfs.scan_apk(upload_response['hash'])
                            scan_thread = threading.Thread(target=scan_apk_in_thread, args=(upload_response['hash'],))
                            scan_thread.start() # Start the thread
                        except Exception as e:
                            logger.error(f"get_server_stats - Failed to process {target}: {e}")
        return stats

    except Exception as e:
        logger.error(f"get_server_stats - Failed to get server stats: {e}")
        return {"success": False, "message": str(e)}


def scan_apk_in_thread(hash_value):
    try:
        logger.info(f"Starting APK scan in a separate thread for hash: {hash_value}")
        scan_response = mobfs.scan_apk(hash_value)
        logger.info(f"Scan response received: {scan_response}")
    except Exception as e:
        logger.error(f"Error occurred during APK scan: {e}")

def get_targets(total_running_scan_count, docker_type):
    url = "https://panel.hunterbounter.com/target"
    headers = {
        "Content-Type": "application/json",
    }
    payload = {
        "total_running_scan_count": total_running_scan_count,
        "docker_type": docker_type
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        logging.info(f"Response: {response.json()}")
        if response.status_code == 200:
            print(f"Success: {response.json()}")
            return response.json()
        else:
            print(f"Failed to get targets: {response.text}")
            return {"success": False, "message": response.text}
    except Exception as e:
        print(f"Failed to get targets: {e}")
        return {"success": False, "message": str(e)}


# Example usage


def send_telemetry(json_stats):
    logging.info("Sending telemetry data")
    try:
        response = requests.post('https://panel.hunterbounter.com/telemetry/save', data=json_stats)
        if response.status_code != 200:
            print(f"Failed to send telemetry data: {response.text}")
    except Exception as e:
        print(f"Failed to send telemetry data: {e}")


def send_scan_telemetry():
    try:
        scan_results = mobfs.get_scans_list()
        print("Scan Results : ", scan_results)


        # scan results is raise ?
        if scan_results is None or scan_results == {}:
            logging.info("Scan results is None")
            return
            # to json

        # add machineId
        hostname = get_host_name()

        cloud_scan_results = []
        # Add machine ID to each scan result
        for result in scan_results['content']:
            result['machine_id'] = hostname
            result['agent_type'] = "mobfs"
            cloud_scan_results.append(result)
            mobfs.save_pdf_cloud(result['MD5'], result['FILE_NAME'])



        json_result = json.dumps(scan_results, indent=4)

        response = requests.post('https://panel.hunterbounter.com/scan_results/mobfs/save', data=json_result,
                                 headers={"Content-Type": "application/json"})
        if response.status_code != 200:
            print(f"Failed to send scan results: {response.text}")
    except Exception as e:
        print(f"Failed to send scan results: {e}")


server_stats = get_server_stats()
json_stats = json.dumps(server_stats, indent=4)
send_telemetry(json_stats)
