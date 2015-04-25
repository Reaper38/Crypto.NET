// StringCrypt.cs -  Simple string encryption and decryption with any SymmetricAlgorithm

//============================================================================
// CryptoNet - A cryptography library for C#
// 
// Copyright (C) 2008  Nils Reimers (www.php-einfach.de)
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//=============================================================================


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace CryptoNet
{

    /// <summary>
    /// An easy-to-use string encryption class
    /// </summary>
    public class StringCrypt : IDisposable
    {
        protected byte[] key;
        protected string keyChecksum;

        protected SymmetricAlgorithm algorithm = new Twofish();
        protected CryptRand rng = CryptRand.Instance;
       

        private const int saltLength = 8;


        public byte[] Key
        {
            get { return key; }
            set
            {
                if (key != value)
                {
                    key = value;
                    keyChecksum = CalculateKeyChecksum();
                }
            }
        }

        public string KeyChecksum
        {
            get { return keyChecksum;  }
        }

        public SymmetricAlgorithm Algorithm
        {
            get { return algorithm; }
            set { algorithm = value; }
           
        }

        public StringCrypt()           
        {
            key = GenKey(128);
            Initialize();
        }

        public StringCrypt(string password)
        {
            byte[] key = KeyStrengthening(password);
            this.key = key;                  
            
            Initialize();        
        }

        public StringCrypt(byte[] key)
        {
            this.key = key;
            Initialize();
        }


        public string Encrypt(string s)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(s);           

            MemoryStream memStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(memStream, algorithm.CreateEncryptor(key, algorithm.IV), CryptoStreamMode.Write);
            memStream.Write(algorithm.IV, 0, algorithm.IV.Length);
            
            cStream.Write(buffer, 0, buffer.Length);
            cStream.Flush();          
            cStream.Close();

            byte[] cipher = memStream.ToArray();

            memStream.Dispose();
            memStream.Close();
            
            Array.Clear(buffer, 0, buffer.Length);

            return KeyChecksum + "$" + Convert.ToBase64String(cipher);
        }

        public string Decrypt(string s)
        {
            if(!s.Contains("$"))
                throw new ArgumentException("Bad format");


            string checkSum = s.Substring(0, s.IndexOf('$'));

            if (!VerifyKey(key, checkSum))
                throw new CryptographicException("Wrong key");
            

            byte[] buffer = Convert.FromBase64String(s.Substring(s.IndexOf('$') + 1));
            byte[] iv = new byte[algorithm.BlockSize >> 3];

            Buffer.BlockCopy(buffer, 0, iv, 0, iv.Length);
            
                     


            MemoryStream memStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(memStream, algorithm.CreateDecryptor(key, iv), CryptoStreamMode.Write);


            cStream.Write(buffer, (algorithm.BlockSize>>3), (buffer.Length-(algorithm.BlockSize>>3)));
            cStream.Flush();            
            cStream.Close();

            byte[] plain = memStream.ToArray();

            memStream.Dispose();
            memStream.Close();

            Array.Clear(buffer, 0, buffer.Length);

            return Encoding.UTF8.GetString(plain);
        }


        protected virtual void Initialize()
        {           
            algorithm.Key = key;
            algorithm.Mode = CipherMode.CBC;
            algorithm.Padding = PaddingMode.PKCS7;           

            keyChecksum = CalculateKeyChecksum();
        }

        protected virtual string CalculateKeyChecksum()
        {
          
            byte[] salt = new byte[saltLength];
            rng.GetBytes(salt);

            return CalculateKeyChecksum(salt, this.key); 
            
        }

        protected virtual string CalculateKeyChecksum(byte[] salt, byte[] key)
        {
            HashAlgorithm hash = MD5.Create();           
            byte[] comb = new byte[salt.Length + key.Length];
            byte[] result = new byte[salt.Length + (hash.HashSize >> 3)];
            byte[] hashvalue;

            
            Buffer.BlockCopy(salt, 0, comb, 0, salt.Length);
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);

            Buffer.BlockCopy(key, 0, comb, salt.Length, key.Length);

            hashvalue = hash.ComputeHash(comb);
            Buffer.BlockCopy(hashvalue, 0, result, salt.Length, hashvalue.Length);


            return Convert.ToBase64String(result);
        }



        public bool VerifyKey(string password, string keyChecksum)
        {
            byte[] buffer = Convert.FromBase64String(keyChecksum);
            byte[] salt = new byte[saltLength];
            byte[] key = KeyStrengthening(password);

            Buffer.BlockCopy(buffer, 0, salt, 0, salt.Length);

            string calc = CalculateKeyChecksum(salt, key);

            return (keyChecksum == CalculateKeyChecksum(salt, key));
        }

        protected bool VerifyKey(byte[] key, string keyChecksum)
        {
            byte[] buffer = Convert.FromBase64String(keyChecksum);
            byte[] salt = new byte[saltLength];

            Buffer.BlockCopy(buffer, 0, salt, 0, salt.Length);

            return (keyChecksum == CalculateKeyChecksum(salt, key));
        }



        protected virtual byte[] GenKey(int bits)
        {
            byte[] key = new byte[bits >> 8];
            rng.GetBytes(key);
            return key;
        }

        protected virtual byte[] KeyStrengthening(string password)
        {
            KeyStrengthening deriveKey = new KeyStrengthening();
            deriveKey.DefaultOutputLength = KeyOutputLength._128;           

            byte[] key = deriveKey.ComputeHash(password);           

            return key;           
        }

        #region IDisposable Member

        public void Dispose()
        {
            for (int i = 0; i < key.Length; i++)
                key[i] = 0x00;

            key = null;
        }

        #endregion
    }
}
