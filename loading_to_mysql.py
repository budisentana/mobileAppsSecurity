# This script is use to load static analysis result from json to mysql

import MySQLdb
import json
import os

def dbconnect():
    try:
        db = MySQLdb.connect(
            host='localhost',
            user='root',
            passwd='Ch4nc3f0rm3!',
            db='mapps_malware_analysis'
        )
        # print("connected")
    except Exception as e:
        print(e+"Can't connect to database")
    return db

def insert_permission(data_file):   
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to permission table')           
            json_permission = json_data['permissions']
            db = dbconnect()
            for line in json_permission:
                status = json_permission[line]['status']
                info = json_permission[line]['info']
                cursor = db.cursor()
                cursor.execute("""
                INSERT INTO permission(file_name, permission_type, status, info) \
                VALUES (%s,%s,%s,%s) """,(file_name, line,status,info))
                cursor.close()
                # print(file_name +','+ line + ','+status)
                db.commit()
            db.close()
    except Exception as e:
        print(e)

def insert_virus_total(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to virus total table')
            json_vt = json_data['virus_total']['scans']
            db = dbconnect()
            for line in json_vt:
                status = json_vt[line]['detected']
                print(status)
                if status == True:
                    malware_type = json_vt[line]['result']
                    print(line+str(malware_type))
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO virus_total(file_name, AV_provider, detection) \
                    VALUES (%s,%s,%s) """,(file_name, line, malware_type))
                    cursor.close()
                    db.commit()
            db.close()
    except Exception as e:
        print(e)

def insert_android_api(data_file):
    try:
        # print(data_file)
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to android api table')
            json_android_ip = json_data['android_api']
            # print(json_android_ip)
            for line in json_android_ip:
                # print(line)
                api_type = line
                db = dbconnect()
                for item in json_android_ip[line]:
                    path_file = json_android_ip[line]['path']
                    file_num = len(path_file)
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO android_api(file_name, api_type, file_num) \
                    VALUES (%s,%s,%s) """,(file_name, api_type,file_num))
                    cursor.close()
                    db.commit()
                db.close()
    except Exception as e:
        print(e)

def insert_manifest_analysis(data_file):
    try:
        # print(data_file)
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to manifest table')
            json_manifest = json_data['manifest_analysis']
            db = dbconnect()
            for i,line in enumerate(json_manifest):
                severity = json_manifest[i]['stat']
                if severity in ['high']:
                    issue = str(json_manifest[i]['component'])
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO manifest_analysis(file_name,issue,severity) \
                    VALUES (%s,%s,%s) """,(file_name,issue,severity))
                    cursor.close()
                    db.commit()
                    print(file_name+issue+severity)
            db.close()
    except Exception as e:
        print(e)

def insert_code_analysis(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to code analysis table')
            json_code = json_data['code_analysis']
            for line in json_code:
                level = json_code[line]['level']
                if level in ['high']:
                    issue = line
                    item_num = len(json_code[line]['path'])
                    db = dbconnect()
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO code_analysis(file_name,issue,severity,files_num) \
                    VALUES (%s,%s,%s,%s) """,(file_name,issue,level,item_num))
                    cursor.close()
                    db.commit()
                    db.close()
    except Exception as e:
        print(e)

def insert_tracker(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to trackers table')
            json_tracker = json_data['trackers']['trackers']
            for i,line in enumerate(json_tracker):
                db = dbconnect()
                for item in json_tracker[i]:
                    provider = item
                    url = json_tracker[i][item]
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO tracker(file_name,tracker_name,url) \
                    VALUES (%s,%s,%s) """,(file_name,provider,url))
                    cursor.close()
                    db.commit()
                db.close()
    except Exception as e:
        print(e)

def insert_browsable_activity(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to browsable activity table')
            json_browse = json_data['browsable_activities']
            db = dbconnect()
            for line in json_browse:
                activity = line
                cursor = db.cursor()
                cursor.execute("""
                INSERT INTO browsable_activities(file_name,activity,intent) \
                VALUES (%s,%s,%s) """,(file_name,activity,''))
                cursor.close()
                db.commit()
            db.close()
    except Exception as e:
        print(e)

def insert_domain_malware(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to domain malware table')
            json_domain = json_data['domains']
            db = dbconnect()
            for line in json_domain:
                domain = line
                status = json_domain[line]['bad']
                geolocation = str(json_domain[line]['geolocation'])
                cursor = db.cursor()
                cursor.execute("""
                INSERT INTO domain_malware(file_name,domain,status,geolocation) \
                VALUES (%s,%s,%s,%s) """,(file_name,domain,status,geolocation))
                cursor.close()
                db.commit()
            db.close()
    except Exception as e:
        print(e)

def insert_apkid_analysis(data_file):
    try:
        with open (data_file,"r") as myfile:
            data = myfile.read()
            json_data = json.loads(data)
            file_name = json_data['file_name']
            print ('inserting '+file_name+' to apkid analysis table')
            json_apkid = json_data['apkid']
            for line in json_apkid:
                dex_class = line
                db = dbconnect()
                for item in json_apkid[line]:
                    detection = item
                    detail = str(json_apkid[line][item])
                    cursor = db.cursor()
                    cursor.execute("""
                    INSERT INTO apkid_analysis(file_name,class_dex,detection,detail) \
                    VALUES (%s,%s,%s,%s) """,(file_name,dex_class,detection,detail))
                    cursor.close()
                    db.commit()
                db.close()
    except Exception as e:
        print(e)

def send_apk():
    PATH = os.path.abspath('')
    json_file = 'com__bedieman__pneumoniaDisease__apk.json'
    obj_file = PATH+'/Code/scan_result/'+json_file
    # insert_permission(obj_file)
    # insert_virus_total(obj_file)
    # insert_android_api(obj_file)
    # insert_manifest_analysis(obj_file)
    # insert_code_analysis(obj_file)
    # insert_tracker(obj_file)
    # insert_browsable_activity(obj_file)
    # insert_domain_malware(obj_file)
    insert_apkid_analysis(obj_file)

send_apk()