using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace FreshFarmMarket.Services
{
    public class EncryptionService
    {
        private readonly byte[] _key;
        private readonly ILogger<EncryptionService> _logger;

        public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
        {
            _logger = logger;

            // Load and decode the Base64 key from appsettings.json
            string base64Key = configuration["EncryptionSettings:Key"];
            byte[] keyBytes = Convert.FromBase64String("VYtCKM9jGupqo2RwJ/8SwhCSTtiBWPDGb6kTYtE0GfU=");
            _logger.LogInformation($"Key Length: {keyBytes.Length} bytes");

            if (string.IsNullOrEmpty(base64Key))
            {
                throw new ArgumentNullException("Encryption Key is missing in appsettings.json");
            }

            _key = Convert.FromBase64String(base64Key);

            if (_key.Length != 16 && _key.Length != 24 && _key.Length != 32)
            {
                throw new ArgumentException("Invalid AES key length. Must be 16, 24, or 32 bytes.");
            }
        }

        public string Encrypt(string data)
        {
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = _key;
                    aes.GenerateIV(); // Random IV for each encryption

                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (var ms = new MemoryStream())
                    {
                        ms.Write(aes.IV, 0, aes.IV.Length); // Store IV

                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(data);
                        }

                        string encryptedData = Convert.ToBase64String(ms.ToArray());
                        _logger.LogInformation($"Encrypted Data: {encryptedData}");
                        return encryptedData;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Encryption Error: {ex.Message}");
                return null;
            }
        }

        public string Decrypt(string encryptedData)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                _logger.LogWarning("Decryption failed: Input is null or empty.");
                return "Input is null or empty";
            }

            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);

                using (var aes = Aes.Create())
                {
                    aes.Key = _key;

                    // Extract IV from the beginning of the encrypted data
                    byte[] iv = new byte[aes.BlockSize / 8];
                    byte[] cipherText = new byte[encryptedBytes.Length - iv.Length];

                    Array.Copy(encryptedBytes, iv, iv.Length);
                    Array.Copy(encryptedBytes, iv.Length, cipherText, 0, cipherText.Length);

                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var ms = new MemoryStream(cipherText))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        string decryptedData = sr.ReadToEnd();
                        return decryptedData;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Decryption Error: {ex.Message}");
                return "Decryption Failed";
            }
        }
    }
}
