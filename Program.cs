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
            var salt = DateTime.UtcNow.ToUnixTime();

            // the AuthServer receives the salt from Ma
            var encryptedToken = RequestFromMobileAcademy(Encrypt(salt.ToString()));
            Console.WriteLine(encryptedToken);
            // and it sends the encryptedToken (sid-salt) back to MA

            // MA decrypt the token
            var decryptedToken = FromAuthServer(encryptedToken);
            Console.WriteLine("SID = {0}, Time = {1}", decryptedToken.Item1, decryptedToken.Item2.ToDateTimeFromUnixTime().ToLocal());
            // that's it!

            Console.Read();
        }

        static string RequestFromMobileAcademy(string encryptedUnixTime)
        {
            var salt = long.Parse(Decrypt(Uri.UnescapeDataString(encryptedUnixTime)));
            var subscriberId = 45865644; // get subscriberId somehow
            var encrypted = Uri.EscapeDataString(Encrypt(String.Format("{0}-{1}", subscriberId, salt)));
            return encrypted;
        }

        static Tuple<int, long> FromAuthServer(string encryptedToken)
        {
            var decrypted = Decrypt(Uri.UnescapeDataString(encryptedToken));
            var decryptedSubscriberId = int.Parse(decrypted.Split('-')[0]);
            var decryptedUnixTime = long.Parse(decrypted.Split('-')[1]);
            return Tuple.Create(decryptedSubscriberId, decryptedUnixTime);
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
