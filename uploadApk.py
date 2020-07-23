import requests
import json
import timeit
import os
import sqlite3
from requests_toolbelt.multipart.encoder import MultipartEncoder

SERVER = "http://127.0.0.1:8000"
APIKEY = '5b082bce9fc386b5a6d392d1ee780801914549dc8bf5d566b6502253955c5579'


def uploadAPK(FILE):
    """Upload File"""
    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (FILE, open(FILE, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    return response.content

def loadtoSQL(stype,hashf,fname):
    """Load the API response to SQL Lite"""
    try:
        db = sqlite3.connect('/home/budi/mobileApps/Code/suspicious_mapps.db')
        cursor = db.cursor()
        cursor.execute('''insert into apk_with_hash values(?,?,?)''',(stype,hashf,fname))
        db.commit
        cursor.close
    except Exception as E:
        print(E)
    finally:
        print('data inserted')
        db.close


fileName ="list_suspicious_apk.txt"
file=open(fileName,"w")
file.truncate(0)
file.close()

path = "/home/budi/mobileApps/appsCollection/Malware/suspicious_mapps_apks"
for root, dirs, files in os.walk(path):
    for file in files:
        with open (fileName,"a") as listfile :
            listfile.write(file + '\n')

with open (fileName) as myfile:
    for line in myfile:
        res_upload = uploadAPK(path + "/" + line.rstrip("\n"))
        field_data= json.loads(res_upload)
        scan_type = field_data.get('scan_type')
        hash_f = field_data.get('hash')
        file_name = field_data.get('file_name')
        loadtoSQL(scan_type,hash_f,file_name)
        
        
