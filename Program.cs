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

namespace Possus
{

    class Program
    {
        protected static readonly ILog log = LogManager.GetLogger(typeof(Program));
        static void Main(string[] args)
        {
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));

            NessusAuth nessusAuth = new NessusAuth(); // setup auth
            NessusOperations nessusOperations = new NessusOperations(); // setup operations
            string nessusServerURL = "";
            try
            {
                //validation need
                Console.Write("nessus server url: ");
                nessusServerURL = Console.ReadLine();
                Console.Write("username: ");
                nessusAuth.UserName = Console.ReadLine();
                Console.Write("password: ");
                nessusAuth.Password = Console.ReadLine();
                Console.Clear();
                log.Info("connected to the server");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while connecting the server");
                throw;
            }

            

            string scanId = "";
            string fileId = "";
            string lastId = "";
            int operation = 0;
            while (true)
            {
                Console.Write("--POSSUS--\n1 - Export last scan\n2 - Export scan by ID\n3 - List all scan IDs\n4 - Get last scan\n5 - Get scan by ID\n6 - Get server status\noperation: ");
                    operation = int.Parse(Console.ReadLine());
                    
                    switch (operation)
                    {
                        case 1:
                            try
                            {
                                Console.Clear();
                                Console.Write("1 - Export last scan\n");
                                lastId = nessusOperations.GetLastScanId(nessusServerURL, nessusAuth);
                                fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, lastId);
                                nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, lastId, fileId, 1);
                                Console.WriteLine("\npress any key for continue");
                                Console.ReadLine();
                                Console.Clear();
                                log.Info("export last scan request completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while exporting last scan");
                                throw;
                            }
                            
                            break;
                        case 2:
                            try
                            {
                                Console.Clear();
                                Console.Write("2 - Export scan by ID. Please write an id:");
                                scanId = Console.ReadLine();
                                Console.Clear();
                                Console.WriteLine(scanId + " result\n");
                                fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, scanId);
                                nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, scanId, fileId, 1);
                                Console.WriteLine("\npress any key for continue");
                                Console.ReadLine();
                                Console.Clear();
                                log.Info("export scan by id request completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while exporting scan by id");
                                throw;
                            }
                            
                            break;
                        case 3:
                            try
                            {
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
                                log.Info("list all scan ids request completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while listing all scan ids");
                                throw;
                            }
                            break;
                        case 4:
                            try
                            {
                                Console.Clear();
                                Console.Write("4 - Get last scan\n");
                                lastId = nessusOperations.GetLastScanId(nessusServerURL, nessusAuth);
                                fileId = nessusOperations.GetFileId(nessusServerURL, nessusAuth, lastId);
                                nessusOperations.GetAndReturnScan(nessusServerURL, nessusAuth, lastId, fileId);
                                Console.WriteLine("\npress any key for continue");
                                Console.ReadLine();
                                Console.Clear();
                                log.Info("get last scan request completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while getting last scan");
                                throw;
                            }
                            break;
                        case 5:
                            try
                            {
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
                                log.Info("get scan by id completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while getting scan by id");
                                throw;
                            }
                            
                            break;
                        case 6: //ok
                            try
                            {
                                Console.Clear();
                                Console.WriteLine("6 - Get server status: " + nessusOperations.GetServerStatus(nessusServerURL));
                                Console.WriteLine("\npress any key for continue");
                                Console.ReadLine();
                                Console.Clear();
                                log.Info("get server status completed");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                log.Error("error while getting server status");
                                throw;
                            }
                            
                            break;

                    }        
            }
        }
    }
}
