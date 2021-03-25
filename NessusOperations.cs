using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Xml;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using System.Linq;
using Possus.JsonOutput;

namespace Possus
{
    public class NessusOperations
    {
        
        RestClient Client;
        RestRequest Request;
        
        //ignore ssl error
        public void SSLHandler()
        {
            Client.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
        }

        //get server status
        public string GetServerStatus(string URL)
        {
            Client = new RestClient(URL + "/server/status");
            SSLHandler();
            Request = new RestRequest(Method.GET);
            
            Request.AddHeader("Content-Type", "application/json");Request.AddHeader("X-Cookie", "token=ae2ce3ae222ec801aba71ddfe46a59ddfcf20df3bca8b749");
            IRestResponse Response = Client.Execute(Request);
            return Response.Content;
        }

        //check status code ok
        public void StatusCodeChecker(IRestResponse Response)
        {
            if (!((int)Response.StatusCode).Equals(200))
            {
                var ex = new Exception(string.Format("{0} - {1}", Response.ErrorMessage, Response.StatusCode));
                ex.Data.Add(Response.StatusCode, Response.ErrorMessage);
                throw ex;
            }
        }

        //get token
        public string GetToken(string URL, NessusAuth na)
        {
            try
            {
                Uri Uri = new Uri(URL + "/session");
                Client = new RestClient(Uri);
                Request = new RestRequest(Method.POST);
                SSLHandler();
                Request.AddParameter("application/json", "{" + "\"username\":" + "\"" + na.UserName + "\"" + "," + "\"password\":" + "\"" + na.Password + "\"" + "}", ParameterType.RequestBody);
                IRestResponse Response = Client.Execute(Request);
                StatusCodeChecker(Response);
                var Details = JObject.Parse(Response.Content);
                return (string)Details["token"]; //return token
            }
            catch (Exception e)
            {

                Console.WriteLine(e.Message);
                return null;
            }
            
        }

        //get id list of all scans
        public List<int> GetAllScans(string URL, NessusAuth na)
        {
            try
            {
                string token = GetToken(URL, na);
                Client = new RestClient("https://localhost:8834/scans/");
                SSLHandler();
                Request = new RestRequest(Method.GET);
                Request.AddHeader("X-Cookie", $"token={token}");
                IRestResponse Response = Client.Execute(Request);
                StatusCodeChecker(Response);
                string jsonData = Response.Content;
                var Details = JObject.Parse(jsonData);
                var Ids = Details["scans"];
                List<int> scanList = new List<int>();
                foreach (var item in Ids)
                {
                    scanList.Add(int.Parse((item["id"]).ToString()));
                }
                return scanList;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
            

        }

        //get last scan id
        public string GetLastScanId(string URL, NessusAuth na)
        {
            List<int> myList = GetAllScans(URL,na);
            return myList.FirstOrDefault().ToString();
        }
        
        //get file
        public string GetFileId(string URL, NessusAuth na, string id)
        {
            try
            {
                string token = GetToken(URL, na);
                Client = new RestClient(URL + "/scans/" + id + "/export");
                SSLHandler();
                var Request = new RestRequest(Method.POST);
                Request.AddHeader("X-Cookie", $"token={token}");
                Request.AddParameter("application/json", "{\n  \"format\":\"nessus\"\n}", ParameterType.RequestBody);
                IRestResponse Response = Client.Execute(Request);
                StatusCodeChecker(Response);
                var Details = JObject.Parse(Response.Content);
                string file = (string)Details["file"];
                return file;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return "";
            }        

        }

        

        //display scan result console OK
        //return it for json output -
        public void GetAndReturnScan(string URL, NessusAuth na,string id,string file)
        {
            try
            {
                string token = GetToken(URL, na);
                Client = new RestClient(URL + "/scans/" + id + "/export/" + file + "/download");
                SSLHandler();
                Request = new RestRequest(Method.GET);
                Request.AddHeader("X-Cookie", $"token={token}");
                IRestResponse Response = Client.Execute(Request);
                StatusCodeChecker(Response);

                //convert and parse xml to json
                string xml = Response.Content;
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);
                string json = JsonConvert.SerializeXmlNode(doc);
                var Details = JObject.Parse(json);

                //write json file for testing
                File.WriteAllText("test.json", json);

                var Vulnerabilities = Details["NessusClientData_v2"]["Report"]["ReportHost"]["ReportItem"];
                List<JToken> Tags = Details["NessusClientData_v2"]["Report"]["ReportHost"]["HostProperties"]["tag"].ToList();
                

                ScanResult scanResult = new ScanResult(); //scan result

                //scan name
                if (Details["NessusClientData_v2"]["Report"]["@name"] != null)
                    scanResult.ScanName = Details["NessusClientData_v2"]["Report"]["@name"].ToString();

                //report generated          
                scanResult.ReportGenerated = DateTime.Now.ToString();



                Host host = new Host(); //host

                //hosts
                foreach (var item in Tags)
                {
                    //target
                    if (item["@name"].ToString() == "host-ip")
                    {
                        if (item["#text"] != null)
                            host.Target = item["#text"].ToString();
                    }
                    //scan start date
                    else if (item["@name"].ToString() == "HOST_START")
                    {
                        if (item["#text"] != null)
                            host.ScanStartDate = item["#text"].ToString();
                    }
                    //scan finish date
                    else if (item["@name"].ToString() == "HOST_END")
                    {
                        if (item["#text"] != null)
                            host.ScanFinishDate = item["#text"].ToString();
                    }
                    //mac address
                    else if(item["@name"].ToString() == "mac-address")
                    {
                        if (item["#text"] != null)
                            host.MacAddress = item["#text"].ToString();
                    }
                    //operating system
                    else if (item["@name"].ToString() == "operating-system")
                    {
                        if (item["#text"] != null)
                            host.OperatingSystem = item["#text"].ToString();
                    }
                }
                
                Console.WriteLine();
                Console.WriteLine("ScanName         : " + scanResult.ScanName);
                Console.WriteLine("ReportGenerated  : " + scanResult.ReportGenerated);
                Console.WriteLine("Target           : " + host.Target);
                Console.WriteLine("ScanStartDate    : " + host.ScanStartDate);
                Console.WriteLine("ScanFinishDate   : " + host.ScanFinishDate);
                Console.WriteLine("MAC Address      : " + host.MacAddress);
                Console.WriteLine("OperatingSystem  : " + host.OperatingSystem);



                Vulnerability vulnerability = new Vulnerability(); //vulnerability

                Console.WriteLine();
                Console.WriteLine("Vulnerabilities");
                foreach (var item in Vulnerabilities)
                {
                    
                    Console.WriteLine("-------------------------------------------");
                    //protocol               
                    if(item["@protocol"]!= null)
                        vulnerability.Protocol = item["@protocol"].ToString();

                    //severity               
                    if (item["@severity"] != null)
                        vulnerability.Severity = item["@severity"].ToString();

                    //pluginid                   
                    if (item["@pluginID"] != null)
                        vulnerability.PluginId = item["@pluginID"].ToString();

                    //name
                    if (item["@pluginName"] != null)
                        vulnerability.Name = item["@pluginName"].ToString();

                    //cvss base score
                    if (item["cvss_base_score"] != null)
                        vulnerability.CvssBaseScore = item["cvss_base_score"].ToString();

                    //description
                    if (item["description"] != null)
                        vulnerability.Description = item["description"].ToString();

                    //solution  
                    if (item["solution"] != null)
                        vulnerability.Solution = item["solution"].ToString();

                    //output
                    if (item["plugin_output"] != null)
                        vulnerability.Output = item["plugin_output"].ToString();
                    
                    Console.WriteLine("protocol         : " + vulnerability.Protocol);
                    Console.WriteLine("severity         : " + vulnerability.Severity);
                    Console.WriteLine("pluginID         : " + vulnerability.PluginId);
                    Console.WriteLine("name             : " + vulnerability.Name);
                    Console.WriteLine("cvssBaseScore    : " + vulnerability.CvssBaseScore);
                    Console.WriteLine("description      : " + vulnerability.Description);
                    Console.WriteLine("solution         : " + vulnerability.Solution);
                    Console.WriteLine("output           : " + vulnerability.Output);
                    
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            

        }

        /*  ignore this
        public void WriteScan(ScanResultCollection src)
        {
            var asd = src.ScanResults.FirstOrDefault();
            src.ScanResults.Remove(asd);
            ScanResult sr = src.ScanResults.FirstOrDefault();
            Host h = sr.Hosts.FirstOrDefault();

            Console.WriteLine();
            Console.WriteLine("ScanName         : " + sr.ScanName);
            Console.WriteLine("ReportGenerated  : " + sr.ReportGenerated);
            Console.WriteLine("Target           : " + h.Target);
            Console.WriteLine("ScanStartDate    : " + h.ScanStartDate);
            Console.WriteLine("ScanFinishDate   : " + h.ScanFinishDate);
            Console.WriteLine("MAC Address      : " + h.MacAddress);
            Console.WriteLine("OperatingSystem  : " + h.OperatingSystem);

            Console.WriteLine("Vulnerabilities");
            foreach (var item in h.Vulnerabilities)
            {
                Console.WriteLine("protocol         : " + item.Protocol);
                Console.WriteLine("severity         : " + item.Severity);
                Console.WriteLine("pluginID         : " + item.PluginId);
                Console.WriteLine("name             : " + item.Name);
                Console.WriteLine("cvssBaseScore    : " + item.CvssBaseScore);
                Console.WriteLine("description      : " + item.Description);
                Console.WriteLine("solution         : " + item.Solution);
                Console.WriteLine("output           : " + item.Output);
            }
        }*/
    }
}
