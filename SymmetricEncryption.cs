using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;

namespace MLearning.Security
{
    [Serializable]
    public class SymmetricAlgorithmKeys : IEquatable<SymmetricAlgorithmKeys>
    {
        public SymmetricAlgorithmKeys()
        {

        }

        public Byte[] SecretKey { get; set; }
        public Byte[] InitVector { get; set; }

        public static SymmetricAlgorithmKeys Create()
        {
            MLearning.Security.SymmetricAlgorithmKeys symmetricKeys = null;

            System.Security.Cryptography.DESCryptoServiceProvider des = new System.Security.Cryptography.DESCryptoServiceProvider();
            byte[] key = des.Key;
            byte[] iv = des.IV;
            symmetricKeys = new MLearning.Security.SymmetricAlgorithmKeys();
            symmetricKeys.SecretKey = key;
            symmetricKeys.InitVector = iv;

            return symmetricKeys;
        }

        #region IEquatable<SymmetricAlgorithmKeys> Members

        public bool Equals(SymmetricAlgorithmKeys other)
        {
            if (other != null)
            {
                return this.SecretKey.SerializeByteArrayToString() == other.SecretKey.SerializeByteArrayToString()
                    &&
                    this.InitVector.SerializeByteArrayToString() == other.InitVector.SerializeByteArrayToString();
            }
            else
                return false;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as SymmetricAlgorithmKeys);
        }

        public override int GetHashCode()
        {
            return SecretKey.SerializeByteArrayToString().GetHashCode() + InitVector.SerializeByteArrayToString().GetHashCode();
        }

        #endregion


        public string DESEncrypt(string val)
        {

            return val.Encrypt(this.SecretKey, this.InitVector, new System.Security.Cryptography.DESCryptoServiceProvider()).SerializeByteArrayToString();
        }

        public string DESDecrypt(string val)
        {

            return val.Decrypt(this.SecretKey, this.InitVector, new System.Security.Cryptography.DESCryptoServiceProvider());
        }


    }
}
