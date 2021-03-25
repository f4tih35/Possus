using System;
using System.Collections.Generic;
using System.Text;

namespace Possus.JsonOutput
{
    public class Host
    {
        
        public string Target { get; set; }
        public string ScanStartDate { get; set; }
        public string ScanFinishDate { get; set; }
        public string MacAddress { get; set; }
        public string OperatingSystem { get; set; }
        public List<Vulnerability> Vulnerabilities { get; set; }
    }
}
