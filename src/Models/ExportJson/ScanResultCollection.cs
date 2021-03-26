using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Possus.JsonOutput
{
    public class ScanResultCollection
    {
        public ICollection<ScanResult> ScanResults { get; set; }

        public ScanResultCollection(ScanResult sr,Host h,List<Vulnerability> vs)
        {
            h.Vulnerabilities = vs;
            sr.Host = h;
            this.ScanResults = new List<ScanResult>(){sr};
            File.WriteAllText($"{sr.ScanName}.json", JsonConvert.SerializeObject(this.ScanResults));
        }
    }
}
