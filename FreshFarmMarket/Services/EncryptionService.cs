using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace FreshFarmMarket.Services
{
    public class EncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public EncryptionService(IConfiguration configuration)
        {
            _key = Convert.FromBase64String(configuration["EncryptionSettings:Key"]);
            _iv = Convert.FromBase64String(configuration["EncryptionSettings:IV"]);
        }

        public string Encrypt(string data)
        {
            using (var aes = Aes.Create())
            {
                using (var encryptor = aes.CreateEncryptor(_key, _iv))
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            using (var sw = new StreamWriter(cs))
                            {
                                sw.Write(data);
                            }
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        public string Decrypt(string encryptedData)
        {
            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
                using (var aes = Aes.Create())
                {
                    using (var decryptor = aes.CreateDecryptor(_key, _iv))
                    {
                        using (var ms = new MemoryStream(encryptedBytes))
                        {
                            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                using (var sr = new StreamReader(cs))
                                {
                                    return sr.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                return "Decryption Failed";
            }
        }
    }
}