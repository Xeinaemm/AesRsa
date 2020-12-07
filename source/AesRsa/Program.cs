using ICSharpCode.SharpZipLib.Core;
using ICSharpCode.SharpZipLib.Zip;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Renci.SshNet;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AesRsaBenchmark
{
    internal class Program
    {
        public static async Task Main()
        {
            var basePath = Directory.GetCurrentDirectory();
            var password = GetUniqueKey(128);
            var timestamp = $"{DateTime.Now:yyyyMMddHHmmssfff}";
            var outputPath = $"{basePath}\\output\\{timestamp}";

            var rsaPublic = $"{basePath}\\files\\public.key";
            var rsaPrivate = $"{basePath}\\files\\private.key";

            var folderToEncrypt = $"{basePath}\\files\\zip";
            var decryptedFolder = $"{outputPath}\\zip";

            var encryptedOutputFile = $"{outputPath}\\{timestamp}.zip";
            var encryptedPasswordFile = $"{outputPath}\\{timestamp}.txt";

            var sftpHost = "sftp.foo.com";
            var sftpUsername = "guest";

            if (!Directory.Exists(outputPath)) Directory.CreateDirectory(outputPath);

            await File.WriteAllTextAsync(encryptedPasswordFile, Convert.ToBase64String(RSAEncrypt(password, rsaPublic)));
            await ZipDirectory(folderToEncrypt, encryptedOutputFile, password);
            UnzipDirectory(encryptedOutputFile, decryptedFolder, RSADecrypt(Convert.FromBase64String(File.ReadAllText(encryptedPasswordFile)), rsaPrivate));
            //await UploadFiles(timestamp, outputPath, rsaPrivate, sftpHost, sftpUsername);
        }

        private static async Task UploadFiles(string timestamp, string outputPath, string rsaPrivate, string sftpHost, string sftpUsername)
        {
            using var client = new SftpClient(sftpHost, sftpUsername, new PrivateKeyFile(File.OpenRead(rsaPrivate)))
            {
                BufferSize = 4096,
                OperationTimeout = TimeSpan.FromHours(1),
            };
            client.Connect();
            client.CreateDirectory(timestamp);
            foreach (var file in Directory.GetFiles(outputPath))
            {
                using var zipUpload = File.OpenRead(file);
                await Task.Factory.FromAsync((callback, stateObject) => client.BeginUploadFile(zipUpload, $"{timestamp}\\{Path.GetFileName(file)}", callback, stateObject), result => client.EndUploadFile(result), null);
            }

            client.Disconnect();
        }

        private static async Task ZipDirectory(string DirectoryPath, string OutputFilePath, string password)
        {
            using var OutputStream = new ZipOutputStream(File.Create(OutputFilePath))
            {
                Password = password,
            };
            OutputStream.SetLevel(9);
            var buffer = new byte[4096];
            foreach (var file in Directory.GetFiles(DirectoryPath))
            {
                var entry = new ZipEntry(Path.GetFileName(file))
                {
                    DateTime = DateTime.Now,
                    AESKeySize = 256,
                };
                OutputStream.PutNextEntry(entry);

                using var fs = File.OpenRead(file);
                int sourceBytes;

                do
                {
                    sourceBytes = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length));
                    await OutputStream.WriteAsync(buffer.AsMemory(0, sourceBytes));
                } while (sourceBytes > 0);
            }
            OutputStream.Finish();
            OutputStream.Close();
        }

        private static void UnzipDirectory(string FileZipPath, string OutputFilePath, string password)
        {
            ZipFile file = null;
            try
            {
                var fs = File.OpenRead(FileZipPath);
                file = new ZipFile(fs)
                {
                    Password = password
                };

                foreach (ZipEntry zipEntry in file)
                {
                    if (!zipEntry.IsFile)
                    {
                        continue;
                    }

                    var fullZipToPath = Path.Combine(OutputFilePath, zipEntry.Name);
                    var directoryName = Path.GetDirectoryName(fullZipToPath);

                    if (directoryName.Length > 0)
                    {
                        Directory.CreateDirectory(directoryName);
                    }

                    using var streamWriter = File.Create(fullZipToPath);
                    StreamUtils.Copy(file.GetInputStream(zipEntry), streamWriter, new byte[4096]);
                }
            }
            finally
            {
                if (file != null)
                {
                    file.IsStreamOwner = true;
                    file.Close();
                }
            }
        }

        private static byte[] RSAEncrypt(string DataToEncrypt, string filename) => ImportPublicKey(filename).Encrypt(Encoding.ASCII.GetBytes(DataToEncrypt), false);

        private static string RSADecrypt(byte[] DataToDecrypt, string filename) => Encoding.ASCII.GetString(ImportPrivateKey(filename).Decrypt(DataToDecrypt, false));

        private static RSACryptoServiceProvider ImportPrivateKey(string keyPath)
        {
            var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)new PemReader(new StringReader(File.ReadAllText(keyPath))).ReadObject()).Private));
            return csp;
        }

        private static RSACryptoServiceProvider ImportPublicKey(string keyPath)
        {
            var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(DotNetUtilities.ToRSAParameters((RsaKeyParameters)(AsymmetricKeyParameter)new PemReader(new StringReader(File.ReadAllText(keyPath))).ReadObject()));
            return csp;
        }

        public static string GetUniqueKey(int size)
        {
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            var data = new byte[4 * size];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            var result = new StringBuilder(size);
            for (var i = 0; i < size; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % chars.Length;

                result.Append(chars[idx]);
            }

            return result.ToString();
        }
    }
}
