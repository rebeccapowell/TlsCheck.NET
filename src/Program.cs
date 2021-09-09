using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CommandLine;
using CommandLine.Text;
using ServiceStack.Text;

namespace TlsChecker
{
    class Program
    {
        public class Options
        {
            [Option('h', "host", Required = false, HelpText = "Set host or IP address to test (no protocol)")]
            public string Host { get; set; }

            [Option('t', "tls", Required = false, HelpText = "Set the TLS versions.")]
            public IEnumerable<string> TlsVersions { get; set; }

            [Option('u', "uri", Required = false, HelpText = "Set URI to test (HTTPS protocol)")]
            public string Uri { get; set; }

            [Option('d', "defer", Required = false, HelpText = "Runs without specifying the ServicePointManager protocols.")]
            public bool Defer { get; set; }
        }

        static void Main(string[] args)
        {
            var parser = new Parser(config => config.HelpWriter = Console.Out);

            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);

            Console.WriteLine("Hit enter to exit");
            Console.ReadLine();
        }

        static void RunOptions(Options opts)
        {
            SecurityProtocolType mkc;
            if (opts.TlsVersions.Any())
            {
                //string[] mk = { "Tls", "Tls11", "Tls12", "Tls13" };
                mkc = opts.TlsVersions.Select(x => {
                    Enum.TryParse(x, out SecurityProtocolType outenum); return outenum;
                }).Aggregate((prev, next) => prev | next);
                Console.WriteLine(string.Format("TLS selected: {0}", mkc.ToString()));
            }
            else
            {
                mkc = SecurityProtocolType.Ssl3 |
                      SecurityProtocolType.Tls |
                      (SecurityProtocolType) 0x300 | //.Tls11
                      (SecurityProtocolType) 0xc00 | //.Tls12
                      (SecurityProtocolType) 0x3000; //.Tls13;
            }

            if (!opts.Defer)
            {
                ServicePointManager.SecurityProtocol = mkc;
            }

            // Handle the Server certificate exchange, to inspect the certificates received
            ServicePointManager.ServerCertificateValidationCallback += TlsValidationCallback;

            if (!string.IsNullOrWhiteSpace(opts.Uri))
            {
                RunWebRequest(opts);
            }
            else
            {
                if (string.IsNullOrWhiteSpace(opts.Host))
                {
                    opts.Host = "api.twilio.com";
                }

                RunHost(opts);
            }
        }

        private static void RunHost(Options opts)
        {
            TlsInfo tlsInfo = null;
            IPHostEntry dnsHost = Dns.GetHostEntry(opts.Host ?? "www.google.com");
            using (TcpClient client = new TcpClient(dnsHost.HostName, 443))
            {
                using (SslStream sslStream = new SslStream(client.GetStream(), false,
                    TlsValidationCallback, null))
                {
                    sslStream.AuthenticateAsClient(dnsHost.HostName, null,
                        (SslProtocols)ServicePointManager.SecurityProtocol, false);
                    tlsInfo = new TlsInfo(sslStream);

                    switch (tlsInfo.ProtocolVersion)
                    {
                        case SslProtocols.None:
                            tlsInfo.ProtocolName = "None";
                            break;
                        case SslProtocols.Ssl2:
                            tlsInfo.ProtocolName = "SSLv2";
                            break;
                        case SslProtocols.Ssl3: // 48
                            tlsInfo.ProtocolName = "SSLv3";
                            break;
                        case SslProtocols.Tls: // 192
                            tlsInfo.ProtocolName = "TLSv1.0";
                            break;
                        case (SslProtocols)0x300: // 768
                            tlsInfo.ProtocolName = "TLSv1.1";
                            break;
                        case (SslProtocols)0xc00: // 3072
                            tlsInfo.ProtocolName = "TLSv1.2";
                            break;
                        case (SslProtocols)0x3000: // 12288
                            tlsInfo.ProtocolName = "TLSv1.3";
                            break;
                        case SslProtocols.Default:
                            tlsInfo.ProtocolName = "Default";
                            break;
                        default:
                            tlsInfo.ProtocolName = "Unknown";
                            break;
                    }
                }
            }

            Console.WriteLine(tlsInfo.Dump());
        }

        private static void RunWebRequest(Options opts)
        {
            Uri requestUri = new Uri(opts.Uri);
            var request = (HttpWebRequest)WebRequest.CreateDefault(requestUri);

            request.Method = WebRequestMethods.Http.Post;
            request.ServicePoint.Expect100Continue = false;
            request.AllowAutoRedirect = true;
            request.CookieContainer = new CookieContainer();

            request.ContentType = "application/x-www-form-urlencoded";
            var postdata = Encoding.UTF8.GetBytes("Some postdata here");
            request.ContentLength = postdata.Length;

            request.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident / 7.0; rv: 11.0) like Gecko";
            request.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            request.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip, deflate;q=0.8");
            request.Headers.Add(HttpRequestHeader.CacheControl, "no-cache");

            using (var requestStream = request.GetRequestStream())
            {
                requestStream.Write(postdata, 0, postdata.Length);
                //Here the request stream is already validated
                SslProtocols sslProtocol = ExtractSslProtocol(requestStream);
                //if (sslProtocol < SslProtocols.Tls12)
                //{
                //    // Refuse/close the connection
                //}
                Console.WriteLine(sslProtocol.Dump());
            }

            try
            {
                var response = (HttpWebResponse)request.GetResponse();
                var r = response.GetResponseStream();
                var stringResponse = new StreamReader(r).ReadToEnd();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static SslProtocols ExtractSslProtocol(Stream stream)
        {
            if (stream is null) return SslProtocols.None;

            BindingFlags bindingFlags = BindingFlags.Instance | BindingFlags.NonPublic;
            Stream metaStream = stream;

            if (stream.GetType().BaseType == typeof(GZipStream))
            {
                metaStream = (stream as GZipStream).BaseStream;
            }
            else if (stream.GetType().BaseType == typeof(DeflateStream))
            {
                metaStream = (stream as DeflateStream).BaseStream;
            }

            var connection = metaStream.GetType().GetProperty("Connection", bindingFlags).GetValue(metaStream, null);
            if (!(bool)connection.GetType().GetProperty("UsingSecureStream", bindingFlags).GetValue(connection, null))
            {
                // Not a Https connection
                return SslProtocols.None;
            }
            var tlsStream = connection.GetType().GetProperty("NetworkStream", bindingFlags).GetValue(connection, null);
            var tlsState = tlsStream.GetType().GetField("m_Worker", bindingFlags).GetValue(tlsStream);
            return (SslProtocols)tlsState.GetType().GetProperty("SslProtocol", bindingFlags).GetValue(tlsState, null);
        }

        private static bool TlsValidationCallback(object sender, X509Certificate CACert, X509Chain CAChain, SslPolicyErrors sslPolicyErrors)
        {
            var certificate = new X509Certificate2(CACert);

            CAChain.Build(certificate);
            return CAChain.ChainStatus.All(cacStatus => !((cacStatus.Status != X509ChainStatusFlags.NoError) & (cacStatus.Status != X509ChainStatusFlags.UntrustedRoot)));
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            //handle errors
            Console.WriteLine(errs.Count());
        }
    }

    public class TlsInfo
    {
        public TlsInfo(SslStream secureStream)
        {
            ProtocolVersion = secureStream.SslProtocol;
            CipherAlgorithm = secureStream.CipherAlgorithm;
            HashAlgorithm = secureStream.HashAlgorithm;
            RemoteCertificate = secureStream.RemoteCertificate;
        }

        public SslProtocols ProtocolVersion { get; set; }
        public CipherAlgorithmType CipherAlgorithm { get; set; }
        public HashAlgorithmType HashAlgorithm { get; set; }
        public X509Certificate RemoteCertificate { get; set; }
        public string ProtocolName { get; set; }
    }
}
