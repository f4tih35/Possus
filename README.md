## Possus

Nessus report prescreener

### Prerequisites

* log4net
* Newtonsoft.Json
* RestSharp

## Usage
- Configure authentication
	- go to Auth/auth-example.json
	- change exampleurl, exampleusername, examplepassword
	- save the file and rename it to auth.json
-  Run the program

## Json Format
```json
[
  {
    "ScanName": "myscan4",
    "ReportGenerated": "3/26/2021 10:56:04 PM",
    "Host": {
      "Target": "192.168.1.1",
      "ScanStartDate": "Thu Mar 25 08:05:59 2021",
      "ScanFinishDate": "Thu Mar 25 08:11:08 2021",
      "MacAddress": "B0:95:75:D7:BE:F6",
      "OperatingSystem": "Broadcom Corporation WPS X1",
      "Vulnerabilities": [
        {
          "Protocol": "",
          "Severity": "",
          "PluginId": "",
          "Name": "",
          "CvssBaseScore": "",
          "Description": "",
          "Solution": "",
          "Output": ""
        },
        {
          "Protocol": "",
          "Severity": "",
          "PluginId": "",
          "Name": "",
          "CvssBaseScore": "",
          "Description": "",
          "Solution": "",
          "Output": ""
        }
      ]
    }
  }
]
```

## Screenshots
![1](/img/1.png?raw=true)  
![2](/img/2.png?raw=true)  
![3](/img/3.png?raw=true)  
![4](/img/4.png?raw=true)
