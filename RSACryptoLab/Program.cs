using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace RSACryptoLab
{
    //class Program
    //{
    //    static RSACryptoServiceProvider rsa;
    //    static void Main(string[] args)
    //    {
    //        rsa = new RSACryptoServiceProvider();
    //        string pubKey = GetKey(false);
    //        string priKey = GetKey(true);
    //        string data = "KimPassword";
    //        string encryptString = Encrypt(pubKey, data);
    //        string decryptString = Decrypt(priKey, encryptString);
    //        Console.WriteLine(encryptString);
    //        Console.WriteLine(decryptString);
    //        Console.WriteLine(data == decryptString);
    //        Console.ReadLine();
    //    }

    //    static string GetKey(bool isPrivate)
    //    {
    //        var publicParameters = rsa.ExportParameters(isPrivate);
    //        return rsa.ToXmlString(isPrivate);
    //    }

    //    static string Encrypt(string pubKey, string data)
    //    {
    //        rsa.FromXmlString(pubKey);
    //        var dataToEncrypt = Encoding.UTF8.GetBytes(data);
    //        var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
    //        var length = encryptedByteArray.Count();
    //        var item = 0;
    //        var sb = new StringBuilder();
    //        foreach (var x in encryptedByteArray)
    //        {
    //            item++;
    //            sb.Append(x);

    //            if (item < length)
    //                sb.Append(",");
    //        }

    //        return sb.ToString();
    //    }

    //    public static string Decrypt(string priKey, string data)
    //    {
    //        var rsa = new RSACryptoServiceProvider();
    //        var dataArray = data.Split(new char[] { ',' });
    //        byte[] dataByte = new byte[dataArray.Length];
    //        for (int i = 0; i < dataArray.Length; i++)
    //        {
    //            dataByte[i] = Convert.ToByte(dataArray[i]);
    //        }

    //        rsa.FromXmlString(priKey);
    //        var decryptedByte = rsa.Decrypt(dataByte, false);
    //        return Encoding.UTF8.GetString(decryptedByte);
    //    }
    //}

    class ProgramToken
    {
        static RSACryptoServiceProvider rsa;
        static void Main(string[] args)
        {
            rsa = new RSACryptoServiceProvider();
            for (int i = 0; i < 100; i++)
            {
                DoTest();
            }
            Console.ReadLine();
        }

        static void DoTest()
        {
            string pubKey = GetKey(false);
            string priKey = GetKey(true);
            string data = "KimPassword";
            RSAToken token = new RSAToken();
            string tokenString = token.GenerateTokenString(priKey, data, DateTime.Now.AddDays(3));
            RSAToken decryptToken = token.FromTokenString(pubKey, tokenString);
            Console.WriteLine(tokenString);
            Console.WriteLine(decryptToken.Value);
            Console.WriteLine(data == decryptToken.Value);
        }

        static string GetKey(bool isPrivate)
        {
            var publicParameters = rsa.ExportParameters(isPrivate);
            return rsa.ToXmlString(isPrivate);
        }


        public class RSAToken
        {
            public string Value;
            public DateTime Expires;
            public byte[] Data;
            public byte[] Signature { private set; get; }
            public RSAToken()
            {

            }

            private void Sign(string priKey)
            {
                using (var rsa = new RSACryptoServiceProvider())
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    rsa.FromXmlString(priKey);//使用SignData要使用私鑰
                    Signature = rsa.SignData(Data, sha1);
                }
            }

            public string GenerateTokenString(string priKey, string value, DateTime expires)
            {
                Value = value;
                Expires = expires;
                using (var ms = new MemoryStream())
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(Expires.Ticks);
                    writer.Write(Value);
                    Data = ms.ToArray();
                }
                if (Signature == null)
                {
                    Sign(priKey);
                }
                return Convert.ToBase64String(Data.Concat(Signature).ToArray());
            }

            public RSAToken FromTokenString(string pubOrPriKey, string tokenString)
            {
                var buffer = Convert.FromBase64String(tokenString);
                var data = buffer.Take(buffer.Length - 128).ToArray();
                var sig = buffer.Skip(data.Length).Take(128).ToArray();
                using (var rsa = new RSACryptoServiceProvider())
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    rsa.FromXmlString(pubOrPriKey);
                    if (rsa.VerifyData(data, sha1, sig))
                    {
                        using (var ms = new MemoryStream(data))
                        using (var reader = new BinaryReader(ms))
                        {
                            var ticks = reader.ReadInt64();
                            var value = reader.ReadString();
                            var expires = new DateTime(ticks);
                            var token = new RSAToken();
                            token.Expires = expires;
                            token.Value = value;
                            return token;
                        }
                    }
                }
                return null;
            }




        }
    }
}
