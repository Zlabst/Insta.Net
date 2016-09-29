using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace InstaNetLib
{
    class SignatureUtils
    {
        public static string GetSignature(string data)
        {
            HMACSHA256 sha = new HMACSHA256(Encoding.ASCII.GetBytes(Constants.IG_SIG_KEY));
            MemoryStream stream = new MemoryStream(Encoding.ASCII.GetBytes(data));
            var hash = sha.ComputeHash(stream).Aggregate("", (s, e) => s + String.Format("{0:x2}", e), s => s);
            return String.Format("signed_body=" + hash + "." + Uri.EscapeUriString(data) + "&ig_sig_key_version=" + Constants.SIG_KEY_VERSION);
        }
        
        public static string generateUUID(bool type=false)
        {
            Random rand = new Random();

            var uuid = String.Format("{0:x4}{1:x4}-{2:x4}-{3:x4}-{4:x4}-{5:x4}{6:x4}{7:x4}",
                  rand.Next(0,0xffff), rand.Next(0, 0xffff),
                  rand.Next(0, 0xffff),
                  rand.Next(0, 0xffff) | 0x4000,
                  rand.Next(0, 0x3fff) | 0x8000,
                  rand.Next(0, 0xffff), rand.Next(0, 0xffff), rand.Next(0, 0xffff)
                );
            return type ? uuid : uuid.Replace("-", "");
        }
    }
}
