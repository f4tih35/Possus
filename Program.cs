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

namespace Possus
{

    class Program
    {
        static async Task Main(string[] args)
        {
            
            NessusAuth nessusAuth = new NessusAuth();
            NessusOperations nessusOperations = new NessusOperations();
            
            string nessusServerURL = Console.ReadLine();
            nessusAuth.username = Console.ReadLine();
            nessusAuth.password = Console.ReadLine();

            while(true)
            {
                Console.WriteLine("welcome to possus\n1-getLastScan\n2-getScanById\n3-getScanIDs\n4-getStatus");
                try
                {
                    int islem = int.Parse(Console.ReadLine());
                    string id = "";
                    switch (islem)
                    {
                        case 1:
                            nessusOperations.ExportLastScan(nessusServerURL, nessusAuth);
                            break;
                        case 2:
                            id = Console.ReadLine();
                            nessusOperations.ExportScan(nessusServerURL, nessusAuth, id);
                            break;
                        case 3:
                            List<int> idlist = nessusOperations.GetAllScans(nessusServerURL, nessusAuth);
                            foreach (var item in idlist)
                            {
                                Console.WriteLine(item);
                            }
                            break;
                        case 4:
                            Console.WriteLine(nessusOperations.GetServerStatus(nessusServerURL));
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
