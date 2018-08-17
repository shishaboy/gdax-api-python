import base64
import hashlib
import hmac
import time
from requests.auth import AuthBase
import json
import requests

class CoinbaseExchangeAuth(AuthBase):
    """Authentication for Coinbase & GDAX exchange.
    from https://docs.gdax.com/?python#signing-a-message
    def gettime():
        try:
            url='https://api.pro.coinbase.com/time'
            res = requests.get(url) 
            json_res = json.loads(res.text) 
            timestamp= string(json_res['epoch'])
        except: 
            timestamp= string(time.time())
    """
        
    def __init__(self, api_key, secret_key, passphrase):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase

    def __call__(self, request):
        try:
            url='https://api.pro.coinbase.com/time'
            res = requests.get(url) 
            json_res = json.loads(res.text) 
            timestamp= str(json_res['epoch'])
        except: 
            timestamp= str(time.time())
        #timestamp = str(gettime()) #str(time.time())
        message = timestamp + request.method + request.path_url + (request.body or '')
        request.headers.update(get_auth_headers(timestamp, message, self.api_key, self.secret_key,
                                                self.passphrase))
        return request


def get_auth_headers(timestamp, message, api_key, secret_key, passphrase):
    message = message.encode('ascii')
    hmac_key = base64.b64decode(secret_key)
    signature = hmac.new(hmac_key, message, hashlib.sha256)
    signature_b64 = base64.b64encode(signature.digest()).decode('utf-8')
    return {
        'Content-Type': 'Application/JSON',
        'CB-ACCESS-SIGN': signature_b64,
        'CB-ACCESS-TIMESTAMP': timestamp,
        'CB-ACCESS-KEY': api_key,
        'CB-ACCESS-PASSPHRASE': passphrase
    }
