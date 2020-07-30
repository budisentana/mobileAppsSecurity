
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
        print("connected")
    except Exception as e:
        print(e+"Can't connect to database")
    return db

def insert_permission():   
    try:
        db = dbconnect()
        cursor = db.cursor()
        cursor.execute("""
        INSERT INTO permission(file_name, permission_type, status, info) \
             VALUES (%s,%s,%s,%s) """,('coba', 'coba','coba','coba'))
        cursor.close()
        db.commit()
        db.close()
        print('executed')
    except Exception as e:
        print(e)

insert_permission()