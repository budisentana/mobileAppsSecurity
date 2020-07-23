import requests
import json
import timeit
import os
import os.path
import sqlite3
from requests_toolbelt.multipart.encoder import MultipartEncoder


def upload_apk(FILE):
    print("Uploading file")
    multipart_data = MultipartEncoder(fields={'file': (FILE, open(FILE, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    return response.content

def scan_apk(data):
    print("Scanning file")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    return response.content

def json_resp(data):
    print("Generate JSON report")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)
    return response

def check_file():
    fileName = PATH + "/Code/"+"list_suspicious_apk.txt"
    if os.path.isfile(fileName):
        file=open(fileName,"w")
        file.truncate(0)
        file.close()
    else:
        fileName = open(fileName,"w+")
    return fileName

def walk_malware_path():
    for root, dirs, files  in os.walk(mal_path):
        for file in files:
            with open (fileName,"a") as listfile :
                listfile.write(file + '\n')

def send_apk():
    with open (fileName) as myfile:
        for line in myfile:
            res_upload = upload_apk(mal_path + "/" + line.rstrip("\n"))
            # scan apk
            scan_apk(res_upload)
            # save json object / scan result
            field_data = json.loads(res_upload)
            file_name = field_data.get('file_name').replace(".","_")
            # access API for json report
            json_res = json_resp(res_upload)
            json_path = PATH + '/Code/scan_result/'+file_name+'.json'
            dataframe.append(field_data)
            with open (json_path,'w+') as jp:
                json.dump(json_res,jp) 

def write_to_json():
    json_file = PATH + '/Code/apk_with_hash.json'
    with open (json_file,'w+') as dfr:
        json.dump(dataframe,dfr) 


# PATH = os.path.dirname(os.path.realpath(__file__))
SERVER = "http://127.0.0.1:8000"
APIKEY = '5b082bce9fc386b5a6d392d1ee780801914549dc8bf5d566b6502253955c5579'
PATH = os.path.abspath('')
mal_path = PATH + "/appsCollection/Malware/suspicious_mapps_apks"
dataframe=list()
fileName = ''

print(PATH)
fileName = check_file()
walk_malware_path()
send_apk()
write_to_json()

# loadtoSQL()        
        
# def loadtoSQL():    
#     db=sqlite3.connect(PATH + '/Code/'+ 'maaps_with_hash.db')
#     data_json = json.dumps(dataframe)
#     with open(data_json, encoding='utf-8-sig') as json_file:
#         json_data = json.loads(json_file.read())
        
#     #Aim of this block is to get the list of the columns in the JSON file.
#         columns = []
#         column = []
#         for data in json_data:
#             column = list(data.keys())
#             for col in column:
#                 if col not in columns:
#                     columns.append(col)
                                    
#     #Here we get values of the columns in the JSON file in the right order.   
#         value = []
#         values = [] 
#         for data in json_data:
#             for i in columns:
#                 value.append(str(dict(data).get(i)))   
#             values.append(list(value)) 
#             value.clear()
            
#     #Time to generate the create and insert queries and apply it to the sqlite3 database       
#         create_query = "create table if not exists apk_with_hash ({0})".format(" text,".join(columns))
#         insert_query = "insert into apk_with_hash ({0}) values (?{1})".format(",".join(columns), ",?" * (len(columns)-1))    
#         print("insert has started at ")  
#         c = db.cursor()   
#         c.execute(create_query)
#         c.executemany(insert_query , values)
#         values.clear()
#         db.commit()
#         c.close()