using log4net;
using System;
using System.Collections.Generic;
using System.Text;

namespace Possus
{
    public static class AppOperations
    {
        static readonly ILog log = LogManager.GetLogger(typeof(Program));
        static NessusOperations nessusOperations = new NessusOperations();
        static string scanId;
        static string fileId;
        static string lastId;

        public static void ExportLastScan(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.Write("Export last scan\n");
                lastId = nessusOperations.GetLastScanId(connect.Url, connect);
                fileId = nessusOperations.GetFileId(connect.Url, connect, lastId);
                nessusOperations.GetAndReturnScan(connect.Url, connect, lastId, fileId, 1);
                Console.WriteLine("\npress any key for continue");
                Console.ReadLine();
                Console.Clear();
                log.Info("export last scan request completed");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while exporting last scan");
            }
        }

        public static void ExportScanById(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.Write("Export scan by ID. Please write an id:");
                scanId = Console.ReadLine();
                Console.Clear();
                Console.WriteLine(scanId + " result\n");
                fileId = nessusOperations.GetFileId(connect.Url, connect, scanId);
                nessusOperations.GetAndReturnScan(connect.Url, connect, scanId, fileId, 1);
                Console.WriteLine("\npress any key for continue");
                Console.ReadLine();
                Console.Clear();
                log.Info("export scan by id request completed");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while exporting scan by id");
            }
        }

        public static void ListAllScanIds(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.WriteLine("List all scan IDs\n");
                List<int> idlist = nessusOperations.GetAllScans(connect.Url, connect);
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
            }
        }

        public static void GetLastScan(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.Write("Get last scan\n");
                lastId = nessusOperations.GetLastScanId(connect.Url, connect);
                fileId = nessusOperations.GetFileId(connect.Url, connect, lastId);
                nessusOperations.GetAndReturnScan(connect.Url, connect, lastId, fileId);
                Console.WriteLine("\npress any key for continue");
                Console.ReadLine();
                Console.Clear();
                log.Info("get last scan request completed");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while getting last scan");
            }
        }

        public static void GetScanById(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.Write("Get scan by ID. Please write an id:");
                scanId = Console.ReadLine();
                Console.Clear();
                Console.WriteLine(scanId + " result\n");
                fileId = nessusOperations.GetFileId(connect.Url, connect, scanId);
                nessusOperations.GetAndReturnScan(connect.Url, connect, scanId, fileId);
                Console.WriteLine("\npress any key for continue");
                Console.ReadLine();
                Console.Clear();
                log.Info("get scan by id completed");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while getting scan by id");
            }
        }

        public static void GetServerStatus(Connect connect)
        {
            try
            {
                Console.Clear();
                Console.WriteLine("Get server status: " + nessusOperations.GetServerStatus(connect.Url));
                Console.WriteLine("\npress any key for continue");
                Console.ReadLine();
                Console.Clear();
                log.Info("get server status completed");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                log.Error("error while getting server status");
            }
        }
    }
}
