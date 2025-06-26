using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using Org.BouncyCastle.Crypto;

namespace Pass_Manager
{
    public class Encryption
    {
        public static byte[] GenerateSalt()
        {
            byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
            return salt;
        }
        public static string GenerateRandomPassword()
        {
            string characters = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm`!@#$%^&*()_-+={}[]|;:',<>./?1234567890";
            int passwordLength = 15;
            string password = "";

            for(int i = 0; i < passwordLength; i++)
            {
                int index = RandomNumberGenerator.GetInt32(0, characters.Length);
                password += characters[index];
            }

            return password;
        }
        public static byte[] GenerateIv()
        {
            using (Aes myAes = Aes.Create())
            {
                return myAes.IV;
            }
        }
        public static byte[] GenerateKey(string email, string password, byte[] salt)
        {
            // A secure string to be hashed
            string keyString = email + password;
            // Hash the string to create the key
            return Rfc2898DeriveBytes.Pbkdf2(keyString, salt, 500000, new HashAlgorithmName("SHA256"), 32);
        }
        public static string EncryptPassword_PBKDF2(string password, byte[] salt)
        {
            byte[] encryptedPassword = Rfc2898DeriveBytes.Pbkdf2(password, salt, 250000, new HashAlgorithmName("SHA512"), 64);
            return Convert.ToBase64String(encryptedPassword);
        }
        public static string EncryptPassword_AES(string password, byte[] key, string Iv)
        {
            byte[] encrypted;
            using (Aes myAes = Aes.Create())
            {
                encrypted = EncryptStringToBytes_Aes(password, key, Convert.FromBase64String(Iv));
            }
            return Convert.ToBase64String(encrypted);
        }
        public static string DecryptPassword_AES(string encryption, byte[] key, string Iv)
        {
            using (Aes myAes = Aes.Create())
            {
                return DecryptStringFromBytes_Aes(Convert.FromBase64String(encryption), key, Convert.FromBase64String(Iv));
            }
        }

        public static string KeyMask()
        {
            string pwd = "";
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pwd.Length > 0)
                    {
                        pwd = pwd.Substring(0, pwd.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else if (i.KeyChar != '\u0000') // KeyChar == '\u0000' if the key pressed does not correspond to a printable character, e.g. F1, Pause-Break, etc
                {
                    pwd += i.KeyChar;
                    Console.Write("*");
                }
            }
            return pwd;
        }

        // THESE ARE THE FUNCTIONS FROM MICROSOFT DOCUMENTATION
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-9.0#code-try-2
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
