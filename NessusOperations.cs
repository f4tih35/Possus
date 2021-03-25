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

namespace Possus
{
    public class NessusOperations
    {
        
        RestClient client;
        RestRequest request;
        
        //ssl ignore
        public void SSLHandler()
        {
            client.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
        }

        public string GetServerStatus(string URL)
        {
            client = new RestClient(URL + "/server/status");
            SSLHandler();
            request = new RestRequest(Method.GET);
            
            request.AddHeader("Content-Type", "application/json");request.AddHeader("X-Cookie", "token=ae2ce3ae222ec801aba71ddfe46a59ddfcf20df3bca8b749");
            IRestResponse response = client.Execute(request);
            return response.Content;
        }

        public void StatusCodeChecker(IRestResponse response)
        {
            if (!((int)response.StatusCode).Equals(200))
            {
                var ex = new Exception(string.Format("{0} - {1}", response.ErrorMessage, response.StatusCode));
                ex.Data.Add(response.StatusCode, response.ErrorMessage);  // store "3" and "Invalid Parameters"
                throw ex;
            }
        }

        //get token
        public string GetToken(string URL, NessusAuth na)
        {
            try
            {
                Uri uri = new Uri(URL + "/session");
                client = new RestClient(uri);
                request = new RestRequest(Method.POST);
                SSLHandler();
                request.AddParameter("application/json", "{" + "\"username\":" + "\"" + na.username + "\"" + "," + "\"password\":" + "\"" + na.password + "\"" + "}", ParameterType.RequestBody);
                IRestResponse response = client.Execute(request);
                StatusCodeChecker(response);
                var details = JObject.Parse(response.Content); //content to json
                return (string)details["token"]; //return token
            }
            catch (Exception e)
            {

                Console.WriteLine(e.Message);
                return "";
            }
            
        }

        public List<int> GetAllScans(string URL, NessusAuth na)
        {
            try
            {
                string token = GetToken(URL, na);
                client = new RestClient("https://localhost:8834/scans/");
                SSLHandler();
                request = new RestRequest(Method.GET);
                request.AddHeader("X-Cookie", $"token={token}");
                IRestResponse response = client.Execute(request);
                StatusCodeChecker(response);
                string jsonData = response.Content;
                var details = JObject.Parse(jsonData);
                var idler = details["scans"];
                List<int> liste = new List<int>();
                foreach (var item in idler)
                {
                    liste.Add(int.Parse((item["id"]).ToString()));
                }
                return liste;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }

            
        }

        //get sonuncu id
        public void ExportLastScan(string URL, NessusAuth na)
        {
            List<int> myList = GetAllScans(URL,na);
            ExportScan(URL, na, myList.FirstOrDefault().ToString());
        }
        
        public void ExportScan(string URL, NessusAuth na, string id)
        {
            

            try
            {
                string token = GetToken(URL, na);
                //string id = GetLastScan(na);
                client = new RestClient(URL + "/scans/" + id + "/export");
                SSLHandler();
                var request = new RestRequest(Method.POST);
                request.AddHeader("X-Cookie", $"token={token}");
                request.AddParameter("application/json", "{\n  \"format\":\"nessus\"\n}", ParameterType.RequestBody);
                IRestResponse response = client.Execute(request);
                StatusCodeChecker(response);
                //Console.WriteLine(response.Content);
                string jsonData = response.Content;
                var details = JObject.Parse(jsonData);
                string file = (string)details["file"];
                //Console.WriteLine(file);
                DownloadScan(URL, na, id, file);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }        

        }

        public void DownloadScan(string URL, NessusAuth na,string id,string file)
        {
            try
            {
                //buradan aldiklarimi kullanacagim
                string token = GetToken(URL, na);
                client = new RestClient(URL + "/scans/" + id + "/export/" + file + "/download");
                SSLHandler();
                request = new RestRequest(Method.GET);
                request.AddHeader("X-Cookie", $"token={token}");
                IRestResponse response = client.Execute(request);
                StatusCodeChecker(response);
                //convert xml to json
                string xml = response.Content;
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);
                string json = JsonConvert.SerializeXmlNode(doc);
                var details = JObject.Parse(json);
                //File.WriteAllText(@"test.json", json);
                //write
                var Vulnerabilities = details["NessusClientData_v2"]["Report"]["ReportHost"]["ReportItem"];
                //var macAddress = details["NessusClientData_v2"]["Report"]["ReportHost"]["HostProperties"]["tag"][11]["#text"];
                //var ScanFinishDate = details["NessusClientData_v2"]["Report"]["ReportHost"]["HostProperties"]["tag"][1]["#text"];
                //var ScanStartDate = details["NessusClientData_v2"]["Report"]["ReportHost"]["HostProperties"]["tag"][21]["#text"];
                //var Target = details["NessusClientData_v2"]["Policy"]["Preferences"]["ServerPreferences"]["preference"][6]["value"];
                var ScanName = details["NessusClientData_v2"]["Report"]["@name"];

                Console.WriteLine("ScanName");
                Console.WriteLine(ScanName);

                Console.WriteLine("Target");
                Console.WriteLine("Target");

                Console.WriteLine("ReportGenerated");
                Console.WriteLine(DateTime.Now);

                Console.WriteLine("ScanStartDate");
                Console.WriteLine("ScanStartDate");

                Console.WriteLine("ScanFinishDate");
                Console.WriteLine("ScanFinishDate");

                Console.WriteLine("MacAddress");
                Console.WriteLine("MacAddress");

                foreach (var item in Vulnerabilities)
                {
                    Console.WriteLine("***************************************************************");
                    Console.WriteLine("-----------------");
                    Console.WriteLine("OperatingSystem");
                    Console.WriteLine("...");
                    Console.WriteLine("-----------------");
                    Console.WriteLine("Vulnerabilities");
                    Console.WriteLine("protocol: " + item["@protocol"]);
                    Console.WriteLine("severity: " + item["@severity"]);
                    Console.WriteLine("pluginID: " + item["@pluginID"]);
                    Console.WriteLine("name: " + item["@pluginName"]);
                    Console.WriteLine("cvssBaseScore: " + item["cvss_base_score"]);
                    Console.WriteLine("description: " + item["description"]);
                    Console.WriteLine("solution: " + item["solution"]);
                    Console.WriteLine("output: " + "...");
                    Console.WriteLine("***************************************************************");

                }
            }
            catch (Exception e)
            {

                Console.WriteLine(e.Message);
            }
            

        }
    }
}
