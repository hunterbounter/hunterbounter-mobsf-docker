FROM opensecurity/mobile-security-framework-mobsf


USER root

WORKDIR /home/mobsf

RUN apt-get update && apt-get install -y \
    libmagic-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY req.txt /home/mobsf/
RUN pip install --no-cache-dir -r /home/mobsf/req.txt

COPY . /home/mobsf/

COPY scripts/entrypoint.sh /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh
RUN chown mobsf:mobsf /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh \
    && chmod +x /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh

USER mobsf

ENV PYTHONPATH=/home/mobsf

ENTRYPOINT ["/bin/sh", "-c", "/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh & /usr/bin/python3 /home/mobsf/agent/main.py"]
