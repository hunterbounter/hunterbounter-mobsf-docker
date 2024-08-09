#!/bin/bash
set -e

python3 /home/mobsf/Mobile-Security-Framework-MobSF/manage.py makemigrations && \
python3 /home/mobsf/Mobile-Security-Framework-MobSF/manage.py makemigrations StaticAnalyzer && \
python3 /home/mobsf/Mobile-Security-Framework-MobSF/manage.py migrate
set +e
python3 /home/mobsf/Mobile-Security-Framework-MobSF/manage.py createsuperuser --noinput --email ""
set -e
mkdir -p /home/mobsf/Mobile-Security-Framework-MobSF/logs && python3 /home/mobsf/Mobile-Security-Framework-MobSF/manage.py create_roles 2>&1 | tee -a /home/mobsf/Mobile-Security-Framework-MobSF/logs/mobsf.log

cd /home/mobsf/Mobile-Security-Framework-MobSF/

# gunicorn komutunu çalıştır
exec gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600 \
    --worker-tmp-dir=/dev/shm --log-level=critical --log-file=- --access-logfile=- --error-logfile=- --capture-output