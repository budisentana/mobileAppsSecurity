import requests
import json
import timeit
import os
import os.path
import sqlite3
from requests_toolbelt.multipart.encoder import MultipartEncoder

def scan_apk(data):
    SERVER = "http://127.0.0.1:8000"
    APIKEY = '5b082bce9fc386b5a6d392d1ee780801914549dc8bf5d566b6502253955c5579'
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    print(response.text)
    return response.content

def send_apk():
    fileName = PATH + '/Code/apk_with_hash.json'
    with open (fileName) as myfile:
        for line in myfile:
            # res_scan = scan_apk(line)
            print('this is string ' +str(line))

# PATH = os.path.dirname(os.path.realpath(__file__))
PATH = os.path.abspath('')
print(PATH)
send_apk()
        
