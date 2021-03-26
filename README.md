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
    [
      {
        "ScanName": "",
        "ReportGenerated": "",
        "Hosts": [
          {
            "Target": "",
            "ScanStartDate": "",
            "ScanFinishDate": "",
            "MacAddress": "",
            "OperatingSystem": "",
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
        ]
      }
    ]

## Screenshots
![1](/img/1.png?raw=true)  
![2](/img/2.png?raw=true)  
![3](/img/3.png?raw=true)  
![4](/img/4.png?raw=true)
