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
        logger.info("upload_apk -> ", response.text)
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
        logger.info("Getting scans list")
        url = f"{self.base_url}/api/v1/scans"
        try:
            logger.info("Getting active scans count")
            logger.info("Api Key %s", self.api_key)
            logger.info("Requesting %s", url)
            logger.info("Headers: %s", self.headers)
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()  # HTTP hatalarını tetikle
            data = response.json()
            return data

        except Exception as e:
            print(f"An error occurred 2 2 : {e}")
            return 0

    def check_mobfs_is_online(self):
        logger.info("Checking if MobSF is online")
        try:
            logger.info("Headers: %s", self.headers)
            response = requests.get(self.base_url, headers=self.headers)
            logger.info("MobSF is online")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"MobSF is offline: {e}")
            return False
        pass

    def active_scans_count(self):
        logger.info("Getting active scans count")
        url = f"{self.base_url}/api/v1/scans"
        try:
            scans = self.get_scans_list()
            # Count 0 ise 0 döner
            contents = scans['content']
            if len(contents) == 0:
                return 0

            active_scans = 0
            for scan in contents:
                if scan.get('APP_NAME', '') == '':
                    active_scans += 1

            return active_scans

        except Exception as e:
            logger.error(f"Failed to get active scans count: {e}")
            return 0
