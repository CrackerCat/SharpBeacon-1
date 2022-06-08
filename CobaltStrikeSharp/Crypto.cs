using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace CobaltStrikeSharp
{
    class Crypto
    {
        //RSA
        static String publicKey = "AMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCll7Vw7Y9R5diaJWbqPpvBoRxDkIk4FZBQ1s+jwK24plib3FkGRokf1yHyAzsg+8CAFsw9LZt5mi7A7+5c0kTE8CAWnhPXYNInnr85/N27JCzM/f4rh4h4dHn+9YGogpHKRLEyMia/6jcJwksoBFwVx769NfkfIHFxci9YKcoOwwIDAQAB";
        static String privateKey = "MMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKWXtXDtj1Hl2JolZuo+m8GhHEOQiTgVkFDWz6PArbimWJvcWQZGiR/XIfIDOyD7wIAWzD0tm3maLsDv7lzSRMTwIBaeE9dg0ieevzn83bskLMz9/iuHiHh0ef71gaiCkcpEsTIyJr/qNwnCSygEXBXHvr01+R8gcXFyL1gpyg7DAgMBAAECgYB+jXEHOyb7KjPdqpP6lZqn4p8dK8sS57gBcAoEVe7uXYL+quoGl8WYZev1b26zCHPX8JRqdP6LcsAkh7mdir0uorBXNSYGlFPTDOwtScd56oBBXcQYYaVK2H8Q37oVMNPGH4QfOfw6IE6G/1FJvmRiGyDhLCKHhNrFhgoqGAP/IQJBANDU3sxJFuO/g+rfc1L+1NeqY7GJPoGG0Y1fJ5wyHOrbyjIGkc5itZKxab8Cq7RDaUKHxmGSy2biHD8Qpv0LjnkCQQDK/qmzKMoQrrVSf9PMsc9hXL4NeA2dJYUZKhtDNxaslyTobR1MAF9ehV9//CY9471b87WYYqtQTFVJnF2lgEgbAkEAhzOqY1xWo3DUuXWdtngh2NcJ4GFYxIdCmGKoxGl1a2CNEcJLF/G0WJrgObhC7lxOg7Jf78AYTC3L19CyLFYVEQJAJcg8gbIn2e8KpK5SF5lIxhBi91LPBd7D5SknJd2NBNak8fXNLCYtmgQtAD9IRuCqkADOXeyPgkSS4z6NV46G3QJBAI8b4XYM+8ECVD6rFfnfxGqegngCRrfeWVO0n5rGy08/QuTJ7SeegLBwwZ5oEwZpNraDWxLl9LP8/oOt5xWsYIo=";

        //AES
        public  static byte[] Key =  new byte[16];
        private static byte[] IV = Encoding.ASCII.GetBytes("abcdefghijklmnop");

        //HMAC
        public static byte[] HMACKey;
        private static string PrivateKeyPkcs8ToXml(string privateKey)
        {
            var privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            var privatElement = new XElement("RSAKeyValue");
            //Modulus
            var primodulus = new XElement("Modulus", Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()));
            //Exponent
            var priexponent = new XElement("Exponent", Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()));
            //P
            var prip = new XElement("P", Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()));
            //Q
            var priq = new XElement("Q", Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()));
            //DP
            var pridp = new XElement("DP", Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()));
            //DQ
            var pridq = new XElement("DQ", Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()));
            //InverseQ
            var priinverseQ = new XElement("InverseQ", Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()));
            //D
            var prid = new XElement("D", Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));

            privatElement.Add(primodulus);
            privatElement.Add(priexponent);
            privatElement.Add(prip);
            privatElement.Add(priq);
            privatElement.Add(pridp);
            privatElement.Add(pridq);
            privatElement.Add(priinverseQ);
            privatElement.Add(prid);

            return privatElement.ToString();
        }


        public static String RSAEncrypt(byte[] PlaintextData)
        {
            byte[] tmp = Convert.FromBase64String(publicKey.Substring(1));
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(tmp);
            string xmlPublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));

            using (RSACryptoServiceProvider RSACryptography = new RSACryptoServiceProvider())
            {
                RSACryptography.FromXmlString(xmlPublicKey);
                int MaxBlockSize = RSACryptography.KeySize / 8 - 11; //加密块最大长度限制 
                if (PlaintextData.Length <= MaxBlockSize)
                    return Convert.ToBase64String(RSACryptography.Encrypt(PlaintextData, false));
                using (MemoryStream PlaiStream = new MemoryStream(PlaintextData))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);
                        Byte[] Cryptograph = RSACryptography.Encrypt(ToEncrypt, false);
                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);
                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }
                    return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
                }
            }
        }


        public static byte[] RSADecrypt(string EncryptString)
        {
            Byte[] CiphertextData = Convert.FromBase64String(EncryptString);
            return RSADecrypt(CiphertextData);
        }


        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="xmlPublicKey"></param>
        /// <param name="EncryptString"></param>
        /// <returns></returns>
        public static byte[] RSADecrypt(byte[] CiphertextData)
        {
            string xmlPrivateKey = PrivateKeyPkcs8ToXml(privateKey.Substring(1));
            using (RSACryptoServiceProvider RSACryptography = new RSACryptoServiceProvider())
            {
                RSACryptography.FromXmlString(xmlPrivateKey);
                int MaxBlockSize = RSACryptography.KeySize / 8;    //解密块最大长度限制

                if (CiphertextData.Length <= MaxBlockSize)
                    return RSACryptography.Decrypt(CiphertextData, false);

                using (MemoryStream CrypStream = new MemoryStream(CiphertextData))
                using (MemoryStream PlaiStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);

                    while (BlockSize > 0)
                    {
                        Byte[] ToDecrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                        Byte[] Plaintext = RSACryptography.Decrypt(ToDecrypt, false);
                        PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                        BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                    }

                    return PlaiStream.ToArray();
                }
            }
        }

        private static byte[] PaddingWithA(byte[] plain)
        {
            if (plain.Length%16 == 0)
            {
                return plain;
            }
            List<byte[]> tmplist = new List<byte[]>();
            byte[] tmp = new byte[16 - (plain.Length % 16)];
            for (int i = 0; i < tmp.Length; i++)
            {
                tmp[i] = 65;
            }
            tmplist.Add(plain);
            tmplist.Add(tmp);
            return Util.BytesCombine(tmplist);
        }
        public static byte[] AESEncrypt(byte[] data)
        {
            byte[] plain = PaddingWithA(data);
            byte[] encrypted;
            using (MemoryStream mstream = new MemoryStream())
            {
                using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider())
                {
                    aesProvider.Mode = CipherMode.CBC;
                    aesProvider.Padding = PaddingMode.None;
                    using (CryptoStream cryptoStream = new CryptoStream(mstream, aesProvider.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plain, 0, plain.Length);
                    }
                    encrypted = mstream.ToArray();
                }
            }
            return encrypted;
        }

        public static byte[] AESDecrypt(byte[] encrypted)
        {
            byte[] plain;
            int count;
            using (MemoryStream mStream = new MemoryStream(encrypted))
            {
                using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider())
                {
                    aesProvider.Mode = CipherMode.CBC;
                    aesProvider.Padding = PaddingMode.None;
                    using (CryptoStream cryptoStream = new CryptoStream(mStream, aesProvider.CreateDecryptor(Key, IV), CryptoStreamMode.Read))
                    {
                        plain = new byte[encrypted.Length];
                        count = cryptoStream.Read(plain, 0, plain.Length);
                    }
                }
            }
            return plain;
        }

        public static byte[] getHMAC(byte[] data)
        {            
            var hash = new HMACSHA256(HMACKey);
            byte[] result = new byte[16];
            byte[] hmac = hash.ComputeHash(data);
            Array.Copy(hmac, 0, result, 0, 16);
            return result;
        }
    }
}
