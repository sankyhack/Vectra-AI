#'https://VECTRA_URL/api/v2.1/detections/?detection_type=scan'  -> Type of Detection
# https://VECTRA_URL/api/v2.1/detections?category=command       -> Category of Detection total 6 categories
#https://VECTRA_URL/api/v2.1/detections/?detection_type=Remote&page=2
#Change the detection type at both places
#Use API guide to know more about vectra detections and replace accordingly 

import requests
import os, ssl

ssl._create_default_https_context = ssl._create_unverified_context

response = requests.get('https://VECTRA_URL/api/v2.1/detections/?detection_type=Remote', headers={'Authorization': 'Token YOUR-API-KEY'}, verify=False)
#print(response.content)

json_response = response.json()
json_response_check = response.json()
count = json_response_check['count']
print(count)
pages = int(count/50)
print(pages)

#Change file path here
with open("C:\\Users\\TEST\\Desktop\\exfil.txt", 'a+') as file:
    for page in range(1, pages+2):
        url = "https://VECTRA_URL/api/v2.1/detections/?detection_type=Remote&page={}".format(page)
        response = requests.get(url, headers={'Authorization': 'Token YOUR-API-KEY'}, verify=False)
        json_response = response.json()
        print(url)
        for key,val in json_response.items():
            
            if(key == "results"):
                #print(val) # prints all the results/dections
                
                for i in val:
                    state = i['state']
                    detection_type = i['detection_type']
                    Source_ip = i['src_ip'] 
                    Start_time = i['first_timestamp']
                    Last_time = i['last_timestamp']
                    threat = str(i['threat'])
                    certainity = str(i['certainty'])
                    domain = None
                    dest_ip = None        
                    try:
                        for d in i['grouped_details']:
                            dest_ip = d['dst_ips']
                            domain  = d['target_domains']
                    except:
                            print(i['url'])
                       
                        
                    Output = state + "," +  detection_type + "," + Source_ip + "," + Start_time + "," + Last_time + "," + str(dest_ip) + "," + str(domain) + "," + threat + "," + certainity
                    file.write(Output)  
                    file.write('\n')        
