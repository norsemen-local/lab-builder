# -------------------------------------------------------------------------------
#    Script Created by Ronen Meshel, Palo Alto Networks.
#    Designed for use with EDU-270 and other Cortex Instructor Led Training
#    Ensure unique <API-KEY> and <TENANT-API-URL> are used below
#    Requires a HTTP-Collector (JSON type) be configured to ingest below "log"
# -------------------------------------------------------------------------------

import requests
def test_http_collector():
    headers = {
        "Authorization": "<API-KEY>",
        "Content-Type": "application/json"
    }
    # Note: the logs must be separated by a new line
    # Integers and Booleans do not require quotation/speech marks "  "  
    # 
    body = '''{
    "Exam": "XSIAM Engineer",
    "ResultValue": 76,
    "Result": "PASS",
    "User": "Ronen Meshel",
    "Email": "RMeshel@paloaltonetworks.com",
    "Verified": true
    }'''
    print("Sending Request")
    res = requests.post(url="<API-URL>",
                        headers=headers,
                        data=body)
    print("Request submitted with status:")
    print(res)
    return res
    # A 200 response indicates a successful log collection. 5xx indicates a potential typo above
test_http_collector()