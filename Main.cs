#if DEBUG
using SDL2;
using SmugBase.Loading;
using SmugBase.Logging;
using SmugBase.Utility;
#endif

using System.Security.Cryptography;
using System.Text;

namespace SmugSecureFiles
{
    public class Main
    {
        public void Run()
        {
            Console.Write("Would you like to secure a file or access a file?"
            + "\nType: 'SECURE' (case-insensitive) to secure a file."
            + "\nType: 'ACCESS' (case-insensitive) to access a file.\n");
            string? response;
            while (true)
            {
                response = Console.ReadLine();
                if (string.IsNullOrEmpty(response))
                {
                    Console.Write("Nothing is not a valid option.");
                    continue;
                }

                switch (response.ToLower())
                {
                    case "secure":
                    case "access":
                        goto hasValidResponse;

                    default:
                        Console.Write("'" + response + "' is not a valid option.");
                        break;
                }
            }

            hasValidResponse:
            if (response == "secure")
            {
                Secure();
            }
            else
            {
                Access();
            }
        }
        private string GetPathFromUser(Func<string, (bool outPut, string? reason)>? isValidPath = null)
        {
            Console.WriteLine("Please provide the path to the file you are looking to modify.");
            string? filePath;
            while (true)
            {
                filePath = Console.ReadLine();
                if (string.IsNullOrEmpty(filePath))
                {
                    Console.WriteLine("Nothing is not a valid file path.");
                    continue;
                }

                if (!File.Exists(filePath))
                {
                    Console.WriteLine("The path you have provided does not direct to an existing file.");
                    continue;
                }

                if (isValidPath == null)
                {
                    return filePath;
                }

                (bool outPut, string? reason) = isValidPath(filePath);
                if (outPut)
                {
                    return filePath;
                }
                else
                {
                    Console.WriteLine("The path you have provided is not valid for the following reason:");
                    Console.WriteLine(reason);
                }
            }
        }

        private string GetPasswordFromUser()
        {
            Console.WriteLine("Please provide the encryption password:");
            string? rawPassword;
            string password;
            while (true)
            {
                rawPassword = Console.ReadLine();
                if (string.IsNullOrEmpty(rawPassword))
                {
                    Console.WriteLine("Nothing is not a valid password.");
                    continue;
                }

                password = rawPassword;
                if (password.Length != 16)
                {
#if DEBUG
                    ContentManager.GetInstance<Logger>().Log("Password length is not the desired length of 16.";
#endif
                    while (password.Length < 16)
                    {
                        password += rawPassword;
                    }
                }
                return password.Substring(0, 16);
            }
        }

        private void Secure()
        {
            string? rawFilePath = GetPathFromUser();

            string filePath = rawFilePath;
            string? fileExtension = null;
            int extensionIndex = rawFilePath.LastIndexOf('.');
            if (extensionIndex != -1)
            {
                filePath = rawFilePath.Substring(0, extensionIndex);
                fileExtension = rawFilePath.Substring(extensionIndex);
            }

            string? passCode = GetPasswordFromUser();
            try
            {
#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Starting encryption.");
#endif
                using FileStream originalFileStream = new FileStream(rawFilePath, FileMode.Open);
                using FileStream securedFileStream = new FileStream(filePath + Program.SecuredExtension, FileMode.Create);
                using Aes aes = Aes.Create();
                aes.Key = Encoding.ASCII.GetBytes(passCode);
                byte[] iv = aes.IV;
                securedFileStream.Write(iv, 0, iv.Length);

                byte[] originalFileBuffer = new byte[originalFileStream.Length];
                originalFileStream.Read(originalFileBuffer);

                using CryptoStream cryptoStream = new CryptoStream(securedFileStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Writing encrypted contents.");
#endif
                cryptoStream.Write(originalFileBuffer);

                Console.WriteLine(filePath + " was successfully encrypted.");
            }
            catch (Exception exception)
            {
                string errorOutput = "Encryption failed with exception: " + exception;
#if DEBUG
                ContentManager.GetInstance<Logger>().Log(errorOutput);
#else
                Console.WriteLine(errorOutput);
#endif
            }
        }

        public void Access()
        {
            string? rawFilePath = GetPathFromUser(attemptedPath => (attemptedPath.EndsWith(Program.SecuredExtension), "Invalid path extension"));

            string filePath = rawFilePath;
            int extensionIndex = rawFilePath.LastIndexOf('.');
            if (extensionIndex != -1)
            {
                filePath = rawFilePath.Substring(0, extensionIndex);
            }

            string? passCode = GetPasswordFromUser();

            Console.WriteLine("Please provide the desired decrypted file extension.");
            string rawFileExtension = Console.ReadLine() ?? string.Empty;
            string fileExtension = rawFileExtension;
            if (!string.IsNullOrEmpty(rawFileExtension) && !rawFileExtension.StartsWith('.'))
            {
                fileExtension = "." + rawFileExtension;
            }

            try
            {
#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Starting decryption.");
#endif

                using FileStream securedFileStream = new FileStream(rawFilePath, FileMode.Open);
                using FileStream newFileStream = new FileStream(filePath + fileExtension, FileMode.Create);
                using Aes aes = Aes.Create();

#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Fetching initialisation vector.");
#endif
                byte[] iv = new byte[aes.IV.Length];
                int numBytesToRead = aes.IV.Length;
                int numBytesRead = 0;
                while (numBytesToRead > 0)
                {
                    int n = securedFileStream.Read(iv, numBytesRead, numBytesToRead);
                    if (n == 0)
                    {
                        break;
                    }

                    numBytesRead += n;
                    numBytesToRead -= n;
                }

#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Reading encrypted stream.");
#endif
                using CryptoStream cryptoStream = new CryptoStream(securedFileStream, aes.CreateDecryptor(Encoding.ASCII.GetBytes(passCode), iv), CryptoStreamMode.Read);
                List<byte> rawSecuredFileBuffer = new List<byte>();
                while (true)
                {
                    int readByte = cryptoStream.ReadByte();
                    if (readByte == -1)
                    {
                        break;
                    }

                    rawSecuredFileBuffer.Add((byte)readByte);
                }
                byte[] securedFileBuffer = rawSecuredFileBuffer.ToArray();
                cryptoStream.Read(securedFileBuffer);

#if DEBUG
                ContentManager.GetInstance<Logger>().Log("Writing decrypted contents.");
#endif
                newFileStream.Write(securedFileBuffer);

                Console.WriteLine(filePath + " was successfully decrypted.");
            }
            catch (Exception exception)
            {
                string errorOutput = "Decryption failed with exception: " + exception;
#if DEBUG
                ContentManager.GetInstance<Logger>().Log(errorOutput);
#else
                Console.WriteLine(errorOutput);
#endif
            }
        }
    }
}
