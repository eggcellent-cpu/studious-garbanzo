using System;
using System.IO;
using System.Security.Cryptography;

namespace FreshFarmMarket.Services
{
    public class EncryptionService
    {
        public string Encrypt(string data)
        {
            using (var aes = Aes.Create())
            {
                // Generate a new random key and IV for each encryption
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] key = aes.Key;
                byte[] iv = aes.IV;

                // Encrypt the data
                using (var encryptor = aes.CreateEncryptor(key, iv))
                using (var ms = new MemoryStream())
                {
                    // Write the IV and encrypted data to the memory stream
                    ms.Write(iv, 0, iv.Length); // Prepend the IV
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(data);
                    }

                    // Combine the key, IV, and encrypted data into a single string
                    string encryptedData = Convert.ToBase64String(ms.ToArray());
                    string keyIvData = Convert.ToBase64String(key) + ":" + Convert.ToBase64String(iv);
                    return $"{keyIvData}:{encryptedData}";
                }
            }
        }

        public string Decrypt(string encryptedDataWithKeyIv)
        {
            try
            {
                // Split the combined string into key, IV, and encrypted data
                string[] parts = encryptedDataWithKeyIv.Split(':');
                if (parts.Length != 3)
                    return "Invalid Data";

                string base64Key = parts[0];
                string base64Iv = parts[1];
                string encryptedText = parts[2];

                byte[] key = Convert.FromBase64String(base64Key);
                byte[] iv = Convert.FromBase64String(base64Iv);
                byte[] encryptedData = Convert.FromBase64String(encryptedText);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    // Decrypt the data
                    using (var decryptor = aes.CreateDecryptor(key, iv))
                    using (var ms = new MemoryStream(encryptedData))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
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