# Installation

## Requirements

Python 3.9+
didkit 0.3.0

## Install

mkdir wallet-link
cd issuer
python3.9 -m venv venv  
. venv/bin/activate  

pip install redis
# pip install Flask-Session
pip install Flask[async]
pip install didkit==0.3.0
pip install  Flask-QRcode
# pip install  gunicorn
pip install requests
pip install pytezos


## Run

python main.py
