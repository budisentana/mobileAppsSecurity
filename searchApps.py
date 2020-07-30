import json
import pprint

json_data = None
with open ('/home/budi/mobileApps/Code/scan_result/com__allistechnology__scrubup__apk.json','r') as rsf:
   
#    ch__inedit__cmv__apk.json
# com__allistechnology__scrubup__apk.json
# com__bedieman__pneumoniaDisease__apk.json

    data = rsf.read()
    json_data = json.loads(data)
    # tracker = json_data['trackers']['trackers'][0]
    # VT = json_data.get('virus_total')
    json_key = json_data.keys() 
    print(json_key)
    # print(tracker)
    # pprint.pprint(json_data['manifest_analysis'][1])
    pprint.pprint(json_data['apkid']['classes.dex'])
    # print(json_data['permissions'])
    # print(json_data['permissions']['status'])
    # print(json_data['virus_total'])
    # pprint.pprint(json_data['file_name'])
    # pprint.pprint(json_data['virus_total'])
    # pprint.pprint(json_data['code_analysis'])
    # pprint.pprint(json_data['trackers']['trackers'][0]['Google AdMob'])
    # pprint.pprint(json_data['exported_count'])
    # pprint.pprint(json_data['files'])
    # pprint.pprint(json_data['playstore_details'])
    # pprint.pprint(json_data['libraries'])  
    # pprint.pprint(json_data['browsable_activities'])
    # pprint.pprint(json_data['domains'])
