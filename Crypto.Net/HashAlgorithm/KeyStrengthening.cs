// KeyStrengthening.cs - Makes a weak key stronger

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
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

namespace CryptoNet
{

    /// <summary>
    /// Outputlength in bits
    /// </summary>
    public enum KeyOutputLength
    {
        _128, _160, _256
    }

    /// <summary>
    /// Makes a weak key (e.g. a password) stronger
    /// </summary>
    public class KeyStrengthening : HashAlgorithm
    {

        //Native hash functions for increasing the speed.
        [DllImport("HashLib.dll")]
        private static extern void md5(byte[] input, int rounds, byte[] output);

        [DllImport("HashLib.dll")]
        private static extern void sha1(byte[] input, int rounds, byte[] output);

        [DllImport("HashLib.dll")]
        private static extern void sha256(byte[] input, int rounds, byte[] output);


       

        private int rounds;
        private KeyOutputLength defaultOutputLength = KeyOutputLength._128;

        /// <summary>
        /// Number of rounds of hashing the input
        /// A higher number of rounds increase the security,
		/// but it take more time for the calculation of a hash-value.            
        /// 
        /// Default value: 262144 (2^18)
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Value has to be less than 50 million</exception>
        public int Rounds
        {
            get { return rounds; }
            set
            {
                if (value > 50000000)
                    throw new ArgumentOutOfRangeException("Value has to be less than 50 million");
                else
                    this.rounds = value;
            }
        }

        /// <summary>
        /// Default Outputlength in bits
        /// </summary>
        public KeyOutputLength DefaultOutputLength
        {
            get { return defaultOutputLength; }
            set { defaultOutputLength = value; }
        }

        public KeyStrengthening()
            : this(262144)
        {     
            
        }

        public KeyStrengthening(int rounds)
            : this(rounds, KeyOutputLength._128)
        {            
        }

        public KeyStrengthening(int rounds, KeyOutputLength defaultOutputLength)
        {
            this.Rounds = rounds;
            this.defaultOutputLength = defaultOutputLength;

            
        }


        public override int HashSize
        {
            get
            {
                if (defaultOutputLength == KeyOutputLength._128)
                    return 128;
                else if (defaultOutputLength == KeyOutputLength._160)
                    return 160;
                else
                    return 256;
            }
        }

        /// <summary>
        /// Calculate a hash from a string
        /// </summary>
        /// <param name="input">Key or Password</param>
        /// <returns>A more secure hashvalue of the input</returns>
        public byte[] ComputeHash(string input)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(input));
        }

        public new byte[] ComputeHash(byte[] input)
        {
            return ComputeHash(input, defaultOutputLength);
        }

        public byte[] ComputeHash(string input, KeyOutputLength length)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(input), length);
        }

        public byte[] ComputeHash(byte[] input, KeyOutputLength length)
        {
            return ComputeHash(input, length, rounds);
        }


        public byte[] ComputeHash(byte[] input, KeyOutputLength length, int rounds)
        {
            HashAlgorithm hash;
            byte[] output;


            if (length == KeyOutputLength._128)
            {
                hash = MD5.Create();
                output = new byte[16];
            }
            else if (length == KeyOutputLength._160)
            {
                hash = SHA1Managed.Create();
                output = new byte[20];
            }
            else
            {
                hash = SHA256Managed.Create();
                output = new byte[32];
            }
           
         

            byte[] inp = hash.ComputeHash(input);

            if (length == KeyOutputLength._128)
                md5(inp, rounds, output);
            else if (length == KeyOutputLength._160)
                sha1(inp, rounds, output);
            else
                sha256(inp, rounds, output);


            return output;            
        }



        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {            
        }

        protected override byte[] HashFinal()
        {
            return null;   
        }

        public override void Initialize()
        {            
        }
    }
}
