'''
Coded by:
  _    _             _            ____                    _            
 | |  | |           | |          |  _ \                  | |           
 | |__| |_   _ _ __ | |_ ___ _ __| |_) | ___  _   _ _ __ | |_ ___ _ __ 
 |  __  | | | | '_ \| __/ _ \ '__|  _ < / _ \| | | | '_ \| __/ _ \ '__|
 | |  | | |_| | | | | ||  __/ |  | |_) | (_) | |_| | | | | ||  __/ |   
 |_|  |_|\__,_|_| |_|\__\___|_|  |____/ \___/ \__,_|_| |_|\__\___|_|   
                                                                       
web : https://hunterbounter.com git : https://github.com/hunterbounter/                                                         

'''

import json
import logging
import os
import sys
import threading
import time

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agent.telemetry import get_server_stats, send_telemetry, send_scan_telemetry
from mobsf import MobSF

app = FastAPI()

mobsf_client = MobSF()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)


@app.post("/upload-and-analyze-apk/")
async def upload_and_analyze_apk(file: UploadFile = File(...)):
    try:
        # Dosyayı bellekte oku
        file_content = await file.read()
        # MobSF API'sine yükle
        upload_response = mobsf_client.upload_apk(file_content, file.filename)
        # APK dosyasını tara
        scan_response = mobsf_client.scan_apk(upload_response['hash'])
        # PDF raporunu al
        pdf_content = mobsf_client.get_pdf_report(upload_response['hash'])
        # PDF raporunu yanıt olarak gönder
        return JSONResponse(content={
            "message": "APK analyzed successfully",
            "report_content": pdf_content.decode('latin1')
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def telemetry_thread():
    while True:
        # check is macos
        if sys.platform == 'darwin':
            return
        server_stats = get_server_stats()
        json_stats = json.dumps(server_stats, indent=4)
        send_telemetry(json_stats)
        time.sleep(10)  # 30 Sec interval


def send_scan_results():
    while True:
        logging.info("init send_scan_results")
        mobfs_online = MobSF().check_mobfs_is_online()
        if mobfs_online:
            send_scan_telemetry()
        logging.info("check_is_mobfs_online() False")
        time.sleep(15)  # 15 Sec interval


if __name__ == "__main__":
    logger.info("init mobfs agent")
    threading.Thread(target=telemetry_thread, daemon=True).start()
    threading.Thread(target=send_scan_results, daemon=True).start()
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8032)
