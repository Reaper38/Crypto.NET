// RSASimple.cs - An easy to use RSA-implementation

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

namespace CryptoNet
{
    public class RSASimple
    {

        private RSAManaged rsa = new RSAManaged();

        public RSASimple()           
        {
        }

        public RSASimple(int dwKeySize)
        {
            rsa.KeySize = dwKeySize;
        }

        public RSASimple(string key)
        {
            rsa.FromXmlString(key);
        }

        public string Encrypt(string data)
        {
            int step = (rsa.KeySize >> 3) - 1;
            byte[] rgb = Encoding.UTF8.GetBytes(data);
            byte[] buffer;
            string result = "";

            for (int i = 0; i < rgb.Length; i += step)
            {
                if ((i + step) > rgb.Length)                
                    buffer = new byte[rgb.Length - i];                
                else
                    buffer = new byte[step];
                
                
                Buffer.BlockCopy(rgb, i, buffer, 0, buffer.Length);
                result += Convert.ToBase64String(rsa.EncryptValue(buffer,true)) + "|";                
            }

            return result.Substring(0, result.Length - 1);
        }

        public string Decrypt(string data)
        {
            string[] split = data.Split('|');         
            List<byte> result = new List<byte>();

            foreach (string s in split)            
                result.AddRange(rsa.DecryptValue(Convert.FromBase64String(s), true)); 

            return Encoding.UTF8.GetString(result.ToArray());
        }

        public string ExportKey(bool includePrivateKey)
        {
            return rsa.ToXmlString(includePrivateKey);
        }

        public void ImportKey(string key)
        {
            rsa.FromXmlString(key);
        }
    }
}
