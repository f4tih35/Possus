using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using Newtonsoft.Json.Linq;
using System.Collections.Specialized;
using System.Collections.Generic;
using Possus.JsonOutput;

namespace Possus
{

    class Program
    {
        static void Main(string[] args)
        {
            

            
            NessusAuth nessusAuth = new NessusAuth(); // setup auth
            NessusOperations nessusOperations = new NessusOperations(); // setup operations

            //validation need
            Console.Write("nessus server url: ");
            string nessusServerURL = Console.ReadLine();
            Console.Write("username: ");
            nessusAuth.UserName = Console.ReadLine();
            Console.Write("password: ");
            nessusAuth.Password = Console.ReadLine();
            Console.Clear();
            while (true)
            {
                Console.Write("\n\n--POSSUS--\n1 - Export last scan\n2 - Export scan by ID\n3 - List all scan IDs\n4 - Get last scan\n5 - Get scan by ID\n6 - Get server status\noperation: ");
                try
                {
                    int operation = int.Parse(Console.ReadLine());
                    string scanId = "";
                    string fileId = "";
                    string lastId = "";
                    switch (operation)
                    {
                        case 1: //export json
                            Console.Clear();
                            Console.Write("1 - Export last scan\n");
                            lastId = nessusOperations.GetLastScanId(nessusServerURL,nessusAuth);
                            fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, lastId);
                            nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, lastId, fileId,1);
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;
                        case 2: //export json
                            Console.Clear();
                            Console.Write("2 - Export scan by ID. Please write an id:");
                            scanId = Console.ReadLine();
                            Console.Clear();
                            Console.WriteLine(scanId + " result\n");
                            fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, scanId);
                            nessusOperations.GetAndReturnScan(nessusServerURL,nessusAuth,scanId,fileId,1);
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;
                        case 3: //ok
                            Console.Clear();
                            Console.WriteLine("3 - List all scan IDs\n");
                            List<int> idlist = nessusOperations.GetAllScans(nessusServerURL, nessusAuth);
                            foreach (var item in idlist)
                            {
                                Console.WriteLine(item);
                            }
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;
                        case 4:
                            Console.Clear();
                            Console.Write("4 - Get last scan\n");
                            lastId = nessusOperations.GetLastScanId(nessusServerURL, nessusAuth);
                            fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, lastId);
                            nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, lastId, fileId);
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;
                        case 5:
                            Console.Clear();
                            Console.Write("5 - Get scan by ID. Please write an id:");
                            scanId = Console.ReadLine();
                            Console.Clear();
                            Console.WriteLine(scanId + " result\n");
                            fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, scanId);
                            nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, scanId, fileId);
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;
                        case 6: //ok
                            Console.Clear();
                            Console.WriteLine("6 - Get server status: " + nessusOperations.GetServerStatus(nessusServerURL));
                            Console.WriteLine("\npress any key for continue");
                            Console.ReadLine();
                            Console.Clear();
                            break;

                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                
            }
        }
    }
}
