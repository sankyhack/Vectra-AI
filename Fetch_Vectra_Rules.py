# Please ensureto change Vectra URL, Token and Path where file will be saved

import requests
import os, ssl

ssl._create_default_https_context = ssl._create_unverified_context

response = requests.get('https://VECTRA_URL/api/v2.1/rules', headers={'Authorization': 'Token YOUR-API-KEY'}, verify=False)
#print(response.content)   #change vectra url and token key

json_response_check = response.json()
count = json_response_check['count']
pages = int(count/50)


for page in range(1, pages+2):
    rule = open("C:\\Users\\TEST\\Desktop\\rule.txt", 'a+')  #Change file path here
    url = "https://VECTRA_URL/api/v2.1/rules?page={}".format(page)
    print(url)
    response = requests.get(url, headers={'Authorization': 'Token YOUR-API-KEY'}, verify=False)
    json_response = response.json()
    print(json_response)
    for key,val in json_response.items():
        #print(key)
        if(key == "results"):
            for i in val:
                description = i['description']
                rule_enable = i['enabled']    
                created_date = i['created_timestamp']
                sip = []
                additional_conditions = []
                sip_cond = ""
                additional_conditions_field = ""
                for k,v in i.items():
                    if (k == "source_conditions"):
                        try:
                            for x,y in v.items():
                                for data in y:
                                    for a,b in data.items():
                                        for anyof in b:
                                            for o,p in anyof.items():
                                                sip_cond = p['field']
                                                for val in p['values']:
                                                    sip.append(val['label'])
                        except:
                            print("no source condition")
                    if (k == "additional_conditions"):
                        try:
                            for x,y in v.items():
                                for data in y:
                                    for a,b in data.items():
                                        for anyof in b:
                                            for o,p in anyof.items():
                                                print()
                                                additional_conditions_field = p['field']
                                                additional_conditions = []
                                                for val in p['values']:
                                                    additional_conditions.append(val['label'])
                        except:
                            print("no additional condition")
                temp_SourceIP = ";".join(sip)
                SourceIP = "[" + temp_SourceIP + "]"
                field = sip_cond
                field_add_cond = additional_conditions_field 
                temp_More_condition = ";".join(additional_conditions)
                More_condition = "[" + temp_More_condition + "]"
                
                Category = i['detection_category']
                Sub_Category = i['detection']
                triage_name = i['triage_category']
                Final_Data = Category + "," + Sub_Category + "," + triage_name + "," + field + "," + SourceIP + "," + field_add_cond + "," + More_condition 
                rule.write(Final_Data)
                rule.write('\n')
                
    
