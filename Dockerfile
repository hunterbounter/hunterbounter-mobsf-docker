FROM opensecurity/mobile-security-framework-mobsf

# Geçici olarak root kullanıcıya geç
USER root

# Çalışma dizinini ayarla
WORKDIR /home/mobsf

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y \
    libmagic-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Gereksinim dosyasını kopyala ve bağımlılıkları yükle
COPY req.txt /home/mobsf/
RUN pip install --no-cache-dir -r /home/mobsf/req.txt

# Python dosyalarını kopyala
COPY . /home/mobsf/

# scripts/entrypoint.sh dosyasını kopyala ve izinlerini değiştir
COPY scripts/entrypoint.sh /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh
RUN chown mobsf:mobsf /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh \
    && chmod +x /home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh

# Normal kullanıcıya geri dön
USER mobsf

ENV PYTHONPATH=/home/mobsf

# Doğru Python yolunu kullanarak ENTRYPOINT'i ayarlayın
ENTRYPOINT ["/bin/sh", "-c", "/home/mobsf/Mobile-Security-Framework-MobSF/scripts/entrypoint.sh & /usr/bin/python3 /home/mobsf/agent/main.py"]
