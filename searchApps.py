import json
import pprint

json_data = None
with open ('/home/budi/mobileApps/Code/scan_result/adiba__rubel__SasthoKonika__apk.json','r') as rsf:
    data = rsf.read()
    json_data = json.loads(data)
    tracker = json_data.get('trackers')
    print(tracker)
# pprint.pprint(json_data)
