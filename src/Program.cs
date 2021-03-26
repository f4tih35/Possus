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
using log4net;
using log4net.Config;
using System.Reflection;
using System.Linq;
using Newtonsoft.Json;
using Possus.ConnectJson;

namespace Possus
{

    class Program
    {
        protected static readonly ILog log = LogManager.GetLogger(typeof(Program));

        static void Main(string[] args)
        {
            Connect connect = new Connect();
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            NessusOperations nessusOperations = new NessusOperations();
            string token;
            int operation;



            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));



            ConnectJsonOperations.ControlFileAndGetAuthInfo(ref connect);



            token = nessusOperations.GetToken(connect.Url, connect);
            if (token != null)
            {
                log.Info(" login test - establishing connection and getting token success");
            }
            else
            {
                log.Error("login test - error while getting token. Please check auth.json file");
                Environment.Exit(0);
            }



            while (true)
            {
                Console.Write("--POSSUS--\n1 - Export last scan\n2 - Export scan by ID\n3 - List all scan IDs\n4 - Get last scan\n5 - Get scan by ID\n6 - Get server status\noperation: ");
                operation = int.Parse(Console.ReadLine());

                switch (operation)
                {
                    case 1:
                        AppOperations.ExportLastScan(connect);
                        break;
                    case 2:
                        AppOperations.ExportScanById(connect);
                        break;
                    case 3:
                        AppOperations.ListAllScanIds(connect);
                        break;
                    case 4:
                        AppOperations.GetLastScan(connect);
                        break;
                    case 5:
                        AppOperations.GetScanById(connect);
                        break;
                    case 6:
                        AppOperations.GetServerStatus(connect);
                        break;

                }
            }
        }
    }
}
