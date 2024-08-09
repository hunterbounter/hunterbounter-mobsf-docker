import json
import os
import time

import requests
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)

LOG_FILE = "/home/mobsf/Mobile-Security-Framework-MobSF/logs/mobsf.log"
API_KEY_PREFIX = 'REST API Key: '
SLEEP_INTERVAL = 5
API_KEY_FOUND = False
CACHED_API_KEY = None


class MobSF:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        logger.info(f"MobSF client initialized")

        global API_KEY_FOUND
        global CACHED_API_KEY
        if not API_KEY_FOUND:
            self.api_key = self.get_api_key()
            CACHED_API_KEY = self.api_key
        else:
            self.api_key = CACHED_API_KEY
        self.headers = {
            'Authorization': str(self.api_key),
            'X-Mobsf-Api-Key': str(self.api_key)
        }

    def clean_api_key(self, api_key):
        # ANSI escape kodlarını temizler
        return api_key.replace('\x1b[1m', '').replace('\x1b[0m', '')

    def get_api_key(self):
        logger.info("Getting API key")
        while True:
            try:
                if not os.path.exists(LOG_FILE):
                    logger.info("Log file does not exist: %s", LOG_FILE)
                    time.sleep(SLEEP_INTERVAL)
                    continue

                with open(LOG_FILE, "r") as f:
                    for line in f:
                        if API_KEY_PREFIX in line:
                            api_key = line.split(API_KEY_PREFIX)[1].strip()
                            logger.info("API key found %s", api_key)
                            global API_KEY_FOUND
                            API_KEY_FOUND = True
                            return self.clean_api_key(api_key)
                    logger.info("API key not found in log file")
                    time.sleep(SLEEP_INTERVAL)
                    continue
            except Exception as e:
                logger.info("Failed to read log file: %s", str(e))
                time.sleep(SLEEP_INTERVAL)

    def upload_apk(self, file_content, file_name):
        logger.info(f"Uploading APK: {file_name}")

        url = f"{self.base_url}/api/v1/upload"
        files = {'file': (file_name, file_content, 'application/vnd.android.package-archive')}

        response = requests.post(url, files=files, headers=self.headers)

        # Correcting the logger statement
        logger.info(f"upload_apk -> {response.text}")

        response.raise_for_status()
        return response.json()

    def scan_apk(self, file_hash):
        logger.info(f"Scanning APK with hash: {file_hash}")
        url = f"{self.base_url}/api/v1/scan"
        data = {
            'hash': file_hash
        }
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = requests.post(url, data=data, headers=headers)

        return response.json()

    def save_pdf_cloud(self, hash,uuid_file_name):
        logger.info(f"Getting PDF report for APK with hash: {hash}")

        headers = {
            'Authorization': self.api_key,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data = {
            'hash': hash,
        }

        response = requests.post(f'{self.base_url}/api/v1/download_pdf', headers=headers, data=data)

        if response.status_code == 200:
            pdf_filename = f"{hash}.pdf"
            with open(pdf_filename, 'wb') as f:
                f.write(response.content)
            logger.info(f"PDF report saved as {pdf_filename}")

            self.upload_pdf_to_server(pdf_filename,uuid_file_name)
        else:
            logger.error(f"Failed to get PDF report: {response.status_code} - {response.text}")

    def upload_pdf_to_server(self, pdf_filename,uuid_file_name):
        logger.info(f"Uploading PDF report {pdf_filename} to server")

        upload_url = 'https://panel.hunterbounter.com/scan_results/save_pdf'

        with open(pdf_filename, 'rb') as f:
            files = {
                'file': (pdf_filename, f, 'application/pdf')
            }
            response = requests.post(upload_url, files=files, data={'uuid_file_name': uuid_file_name})

        if response.status_code == 200:
            logger.info(f"PDF report {pdf_filename} uploaded successfully")
        else:
            logger.error(f"Failed to upload PDF report: {response.status_code} - {response.text}")

    def save_pdf(self, pdf_content, output_path):
        with open(output_path, 'wb') as pdf_file:
            pdf_file.write(pdf_content)

    def analyze_apk(self, file_content, file_name, output_pdf_path):
        logger.info(f"Analyzing APK: {file_name}")
        # Upload the APK
        upload_response = self.upload_apk(file_content, file_name)
        logger.info("APK uploaded successfully.")

        # Scan the APK
        scan_response = self.scan_apk(upload_response['hash'])
        logger.info("APK scanning started.")

        # Retrieve the PDF report
        pdf_content = self.get_pdf_report(upload_response['hash'])
        logger.info("PDF report generated.")

        # Save the PDF report to a file
        self.save_pdf(pdf_content, output_pdf_path)
        logger.info(f"PDF report saved to {output_pdf_path}.")

    def get_scans_list(self):
        logger.info("get_scans_list - Starting to retrieve scans list")

        url = f"{self.base_url}/api/v1/scans"

        try:
            # Aktif tarama sayısını loglama
            logger.info("get_scans_list - Getting active scans count")

            # API anahtarını loglama (Güvenlik açısından bunu üretim ortamında loglamamak daha iyidir)
            logger.info("get_scans_list - Using API Key: %s", self.api_key)

            # İstekte bulunulan URL'i loglama
            logger.info("get_scans_list - Requesting URL: %s", url)

            # İstek için kullanılan başlıkları loglama
            logger.info("get_scans_list - Request Headers: %s", self.headers)

            # GET isteği gönderme
            response = requests.get(url, headers=self.headers)

            # Yanıtın durum kodunu loglama
            logger.info("get_scans_list - Received response: Status Code = %d", response.status_code)

            # HTTP durum kodu hatalarını tetikle
            response.raise_for_status()

            # Yanıtı JSON formatında loglama ve döndürme
            data = response.json()
            logger.info("get_scans_list - Successfully retrieved scans list: %s", data)
            return data

        except requests.exceptions.HTTPError as http_err:
            # HTTP hatalarını loglama
            logger.error("get_scans_list - HTTP error occurred: %s", http_err)
            return 0

        except requests.exceptions.RequestException as req_err:
            # Diğer istek hatalarını loglama
            logger.error("get_scans_list - Request failed: %s", req_err)
            return 0

        except Exception as e:
            # Beklenmedik hataları loglama
            logger.error("get_scans_list - An unexpected error occurred: %s", e)
            return 0

    def check_mobfs_is_online(self):
        logger.info("check_mobfs_is_online - Starting to check if MobSF is online")

        try:
            # Headers bilgisini loglama
            logger.info("check_mobfs_is_online - Request Headers: %s", self.headers)

            # GET isteği yapma
            response = requests.get(self.base_url, headers=self.headers)

            # İstek sonrası loglama
            logger.info("check_mobfs_is_online - Received response: Status Code = %d", response.status_code)

            # Durum kodu kontrolü
            if response.status_code == 200:
                logger.info("check_mobfs_is_online - MobSF is online and reachable")
                return True
            else:
                logger.warning("check_mobfs_is_online - MobSF responded with non-200 status code: %d",
                               response.status_code)
                return False

        except requests.exceptions.RequestException as req_err:
            logger.error("check_mobfs_is_online - Request failed: %s", req_err)
            return False

        except Exception as e:
            logger.error("check_mobfs_is_online - An unexpected error occurred: %s", e)
            return False

    def active_scans_count(self):
        logger.info("active_scans_count - Started counting active scans")

        try:
            # Scan listesini alma
            scans = self.get_scans_list()
            logger.info("active_scans_count - Retrieved scans list: %s", scans)

            # Scan içeriğini alma
            contents = scans.get('content', [])
            logger.info("active_scans_count - Scan content list: %s", contents)

            if not contents:
                logger.info("active_scans_count - No scans found, returning 0")
                return 0

            active_scans = 0

            # Her bir scan'ı kontrol etme
            for index, scan in enumerate(contents):
                app_name = scan.get('APP_NAME')
                logger.info("active_scans_count - Processing scan %d: APP_NAME = '%s'", index, app_name)

                if not app_name:
                    active_scans += 1
                    logger.info("active_scans_count - Scan %d has an empty APP_NAME, incremented active_scans to %d",
                                index, active_scans)

            logger.info("active_scans_count - Total active scans with empty APP_NAME: %d", active_scans)
            return active_scans

        except Exception as e:
            logger.error("active_scans_count - Failed to get active scans count: %s", e)
            return 0
