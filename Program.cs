using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MLearning;
using System.Security.Cryptography;

namespace EncryptionExample
{
    class Program
    {
        static readonly string secretKey = @"CLtHRhSaCYITlXV55F+xL8cD/JWaGU3uRe6QAAIOqmI=";
        static readonly string initVector = @"blWwJ4fPS4Bjid8Z8xZXzQ==";
        static void Main(string[] args)
        {
            var subscriberId = 45865644;
            var salt = DateTime.UtcNow.ToUnixTime();

            var encrypted = Uri.EscapeDataString(Encrypt(String.Format("{0}-{1}", subscriberId, salt)));
            Console.WriteLine(encrypted);
            
            var decrypted = Decrypt(Uri.UnescapeDataString(encrypted));
            var decryptedSubscriberId = int.Parse(decrypted.Split('-')[0]);
            var decryptedUnixTime = long.Parse(decrypted.Split('-')[1]);

            Console.WriteLine("SID = {0}, Time = {1}", decryptedSubscriberId, decryptedUnixTime.ToDateTimeFromUnixTime().ToLocal());

            Console.Read();
        }

        static string Encrypt(string text) {
            var algorithm = SymmetricAlgorithm.Create();

            var encrypted = MLearning.Utilities.Encrypt(text,
                secretKey.DeserializeStringToByteArray(), initVector.DeserializeStringToByteArray(), algorithm).SerializeByteArrayToString();
            return encrypted;
        }

        static string Decrypt(string encrypted)
        {
            var algorithm = SymmetricAlgorithm.Create();

            var decrypted = MLearning.Utilities.Decrypt(encrypted,
                secretKey.DeserializeStringToByteArray(), initVector.DeserializeStringToByteArray(), algorithm);

            return decrypted;

        }
        
    }
}
