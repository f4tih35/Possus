using System;
using System.Collections.Generic;
using System.Text;

namespace Possus.JsonOutput
{
    public class ScanResultCollection
    {
        public ICollection<ScanResult> ScanResults { get; set; }
        /*
        public ScanResultCollection()
        {
            this.ScanResults = new List<ScanResult>(){new ScanResult()
            {
              ScanName="test scan",
              Hosts = new List<Host>(){
                new Host()
                {
                  Target="test target",
                  Vulnerabilities = new List<Vulnerability>(){new Vulnerability(){Protocol="test protocol"}}
                }
              }
            }};
        }
        */
    }
}
