# mgts-w
Checker passwords wirelesses APs (MGTS ISP)
# Installation

## Requirements

* scapy
  
## Installation on Debian

	sudo apt-get update && apt-get install python-dev python-pip python-virualenv network-manager
  virtualenv --no-site-packages mgts-env
  cd mgts-env
  source bin/activate
  git clone https://github.com/xhda/mgts-w.git
  pip install scapy

# Usage
### Run
  python heck.py -scan_int wlan0 -power -75 -con_int wlan1
