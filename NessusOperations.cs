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
using log4net;

namespace Possus
{
    public class NessusOperations
    {
        protected static readonly ILog log = LogManager.GetLogger(typeof(Program));

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
            try
            {
                Client = new RestClient(URL + "/server/status");
                SSLHandler();
                Request = new RestRequest(Method.GET);
                IRestResponse Response = Client.Execute(Request);
                log.Info("request in GetServerStatus is success");
                return Response.Content;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while request in GetServerStatus");
                throw;
            }
            
            
        }

        //check status code ok
        public void StatusCodeChecker(IRestResponse Response)
        {
            if (!((int)Response.StatusCode).Equals(200))
            {
                var ex = new Exception(string.Format("{0} - {1}", Response.ErrorMessage, Response.StatusCode));
                ex.Data.Add(Response.StatusCode, Response.ErrorMessage);
                log.Error("status code is not 200 from StatusCodeChecker");
                throw ex;
            }
            log.Info("status code is 200 from StatusCodeChecker");
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
                log.Info("request in GetToken is success");
                return (string)Details["token"]; //return token
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while request in GetToken");
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
                log.Info("request in GetAllScans is success");
                return scanList;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while request in GetAllScans");
                return null;
            }
            

        }

        //get last scan id
        public string GetLastScanId(string URL, NessusAuth na)
        {
            try
            {
                List<int> myList = GetAllScans(URL, na);
                log.Info("GetLastScanId is success");
                return myList.FirstOrDefault().ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while GetLastScanId");
                throw;
            }
            
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
                log.Info("GetFileId is success");
                return file;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while GetFileId");
                throw;
            }        

        }

        


        public void GetAndReturnScan(string URL, NessusAuth na,string id,string file, int export=0)
        {
            IRestResponse Response;

            try
            {
                string token = GetToken(URL, na);
                Client = new RestClient(URL + "/scans/" + id + "/export/" + file + "/download");
                SSLHandler();
                Request = new RestRequest(Method.GET);
                Request.AddHeader("X-Cookie", $"token={token}");
                Response = Client.Execute(Request);
                StatusCodeChecker(Response);
                log.Info("GetAndReturnScan get request is success");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while get request in GetAndReturnScan");
                throw;
            }

            string json;
            JObject Details;

            try
            {
                //convert and parse xml to json
                string xml = Response.Content;
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);
                json = JsonConvert.SerializeXmlNode(doc);
                Details = JObject.Parse(json);
                log.Info("convert and parse xml to json is success");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while convert and parse xml to json");
                throw;
            }
               

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
                List<Vulnerability> vlns = new List<Vulnerability>();
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
                    vlns.Add(vulnerability);
                    Console.WriteLine("\tprotocol         : " + vulnerability.Protocol);
                    Console.WriteLine("\tseverity         : " + vulnerability.Severity);
                    Console.WriteLine("\tpluginID         : " + vulnerability.PluginId);
                    Console.WriteLine("\tname             : " + vulnerability.Name);
                    Console.WriteLine("\tcvssBaseScore    : " + vulnerability.CvssBaseScore);
                    Console.WriteLine("\tdescription      : " + vulnerability.Description);
                    Console.WriteLine("\tsolution         : " + vulnerability.Solution);
                    Console.WriteLine("\toutput           : " + vulnerability.Output);

                    log.Info("writing info to console is success");
                //export json
                if (export == 1)
                    {
                        try
                        {
                            new ScanResultCollection(scanResult, host, vlns);
                            log.Info("json export is success");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                            log.Error("error while exporting json");
                            throw;
                        }
                    }
                        

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
