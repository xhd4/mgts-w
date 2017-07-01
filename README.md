# mgts-w
Checker passwords wirelesses APs (MGTS ISP)
# install
apt-get update && apt-get install python-virualenv

virtualenv --no-site-packeges mgts-env

cd mgts-env

source bin/source

git clone https://github.com/xhda/mgts-w.git

pip install scapy
