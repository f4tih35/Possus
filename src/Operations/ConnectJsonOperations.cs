﻿using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Possus
{
    public static class ConnectJsonOperations
    {
        public static void ControlFileAndGetAuthInfo(ref Connect connect)
        {
            if (!File.Exists("Auth/auth.json"))
            {
                Console.WriteLine("USAGE:\n"+
                    " - go to Auth folder then auth-example.json file\n"+
                    " - change exampleurl, exampleusername, examplepassword\n"+
                    " - save the file and rename it to auth.json");
                Environment.Exit(0);
            }
            else
            {
                try
                {
                    using (StreamReader r = new StreamReader("Auth/auth.json"))
                    {
                        string json = r.ReadToEnd();
                        connect = JsonConvert.DeserializeObject<Connect>(json);
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
