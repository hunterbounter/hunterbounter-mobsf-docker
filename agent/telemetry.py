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
    try:
        hostname = get_host_name()

        ram_usage = psutil.virtual_memory().percent
        cpu_usage = psutil.cpu_percent()
        active_interfaces = get_active_interfaces()
        disk_usage = psutil.disk_usage('/')

        total_scan_count = mobfs.active_scans_count()

        mobfs_status = mobfs.check_mobfs_is_online()

        if mobfs_status:
            mobfs_status = "online"
        else:
            mobfs_status = "offline"

        uptime = get_uptime()

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

        if mobfs_status == "online":
            logging.info("Getting targets")
            target_response = get_targets(total_scan_count, 4)

            if target_response['success']:
                logging.info("Targets received")
                logging.info("Response -> " + str(target_response))

                targets = target_response['data']['targets']

                if targets is not None:
                    for target in targets:
                        logging.info(f"Downloading APK from {target}")
                        try:
                            file_content = download_file(target)
                            logging.info(f"Uploading APK to MobSF")
                            upload_response = mobfs.upload_apk(file_content, target.split('/')[-1])
                            logging.info(f"Scanning APK with MobSF")
                            scan_response = mobfs.scan_apk(upload_response['hash'])
                            logging.info(f"Scan response: {scan_response}")
                        except Exception as e:
                            logging.error(f"Failed to process {target}: {e}")
        return stats
    except Exception as e:
        print(f"Failed to get server stats: {e}")
        return {"success": False, "message": str(e)}


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
        logging.info("Scan Results (len): " , scan_results)

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
