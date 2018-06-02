# IoTSec

# Setup environment
- Download [anaconda](https://www.anaconda.com/download)
```
# Install anaconda
bash Anaconda-latest-Linux-x86_64.sh

# Clone this repository
git clone https://github.com/janehmueller/IoTSec

# Create environemnt
cd IoTSec
conda env create -f environment.yml

# Activate environment
source activate iot27

# Clone scapy
cd ..
git clone https://github.com/secdev/scapy

# Test scapy dependencies
cd scapy
./run_scapy

# Install scapy in environment
sudo python setup.py install
```
