// SecurePasswordHash.cs - A algorithm for generating a secure hash value of a password

//============================================================================
// CryptoNet - A cryptography library for C#
// 
// Copyright (C) 2007  Nils Reimers (www.php-einfach.de)
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

namespace CryptoNet
{

    /// <summary>
    /// Returns a more secure hash value from a password, using a salt and key strengthening 
    /// </summary>
    public class SecurePasswordHash
    {
        private KeyStrengthening hash;
        private HashAlgorithm hashAlgorithm;
        private int saltLegth = 6;

        public enum HashAlgorithm
        {
            MD5, SHA1, SHA256
        }


        public SecurePasswordHash()
            : this(HashAlgorithm.SHA1)
        {
        }

        public SecurePasswordHash(HashAlgorithm algorithm)
            : this(algorithm, 150000)
        {
        }

        public SecurePasswordHash(HashAlgorithm algorithm, int rounds)
        {
            hash = new KeyStrengthening(rounds);
            if (algorithm == HashAlgorithm.MD5)
                hash.DefaultOutputLength = KeyOutputLength._128;
            else if (algorithm == HashAlgorithm.SHA1)
                hash.DefaultOutputLength = KeyOutputLength._160;
            else
                hash.DefaultOutputLength = KeyOutputLength._256;


            hashAlgorithm = algorithm;
        }

        public string ComputeHash(string password)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        public string ComputeHash(byte[] password)
        {
            return ComputeHash(password, RandomSalt());
        }

        public string ComputeHash(string password, string salt)
        {           
            return ComputeHash(Encoding.UTF8.GetBytes(password), Convert.FromBase64String(salt));
        }

        public string ComputeHash(byte[] password, byte[] salt)
        {
            
            List<byte> tmpRounds = new List<byte>();
            tmpRounds.Add((byte)((hash.Rounds) & 0xFF));
            tmpRounds.Add((byte)((hash.Rounds >> 8) & 0xFF));
            tmpRounds.Add((byte)((hash.Rounds >> 16) & 0xFF));
            tmpRounds.Add((byte)((hash.Rounds >> 24) & 0xFF));

            while (tmpRounds.Count > 0 && tmpRounds[tmpRounds.Count-1] == 0)
                tmpRounds.RemoveAt(tmpRounds.Count-1);

            byte[] bRounds = tmpRounds.ToArray();
                


            string header;
            header = "$" + ((hashAlgorithm == HashAlgorithm.MD5) ? "1" : ((hashAlgorithm == HashAlgorithm.SHA1) ? "2" : "3"));
            header += "$" + Convert.ToBase64String(bRounds);
            header += "$" + Convert.ToBase64String(salt);

            byte[] newPassword = new byte[password.Length + salt.Length];
            password.CopyTo(newPassword, 0);
            salt.CopyTo(newPassword, password.Length);



            return header + "$" + Convert.ToBase64String(hash.ComputeHash(newPassword));
        }


        public byte[] RandomSalt()
        {
            return RandomSalt(saltLegth);
        }

        public byte[] RandomSalt(int length)
        {
            RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();
            byte[] salt = new byte[length];

            rand.GetBytes(salt);

            return salt;
        }


        public bool ComparePassword(string password, string hash)
        {
            if (!hash.Contains("$"))
                throw new ArgumentException("Hash has wrong format");

            string[] header = hash.Split('$');

            KeyOutputLength length;
            int rounds = 0;
            byte[] bSalt;
            byte[] bHash;
            byte[] bPassword = Encoding.UTF8.GetBytes(password);
           

            byte[] tmpRounds;


            if (header[1] == "1")
                length = KeyOutputLength._128;
            else if (header[1] == "2")
                length = KeyOutputLength._160;
            else if (header[1] == "3")
                length = KeyOutputLength._256;
            else
                throw new ArgumentException("Hash has wrong format");


            tmpRounds = Convert.FromBase64String(header[2]);

            for (int i = 0; i < tmpRounds.Length; i++)
                rounds |= tmpRounds[i] << (8 * i);

            bSalt = Convert.FromBase64String(header[3]);
            bHash = Convert.FromBase64String(header[4]);

            byte[] input = new byte[bSalt.Length + bPassword.Length];
            bPassword.CopyTo(input, 0);
            bSalt.CopyTo(input, bPassword.Length);

            byte[] output = this.hash.ComputeHash(input, length, rounds);


            if (output.Length != bHash.Length)
                return false;

            for (int i = 0; i < output.Length; ++i)
                if (output[i] != bHash[i])
                    return false;

            return true;
            
        }

    }
}
