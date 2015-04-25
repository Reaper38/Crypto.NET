// Copyright (c) 2008 Nils Reimers, Crypto.Net
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using CryptoNet;

namespace CryptoNet_Examples
{
    public class Benchmark
    {
        public Benchmark()
        {
            RSAManaged rsa = new RSAManaged();
            rsa.EncryptValue(new byte[10]);


            Console.WriteLine("Benchmark:");
            Console.WriteLine("RijndaelManaged: " + DoBenchmark(new RijndaelManaged()).ToString("") + " Mbit/s");
            Console.WriteLine("RijndaelOpen: " + DoBenchmark(new RijndaelOpen()).ToString("") + " Mbit/s");
            Console.WriteLine("Serpent: " + DoBenchmark(new Serpent()).ToString("") + " Mbit/s");
            Console.WriteLine("Twofish: " + DoBenchmark(new Twofish()).ToString("") + " Mbit/s");
            Console.WriteLine("Mars: " + DoBenchmark(new Mars()).ToString("") + " Mbit/s");

            Console.WriteLine("Blowfish: " + DoBenchmark(new Blowfish()).ToString() + " Mbit/s");
            Console.WriteLine("StreamCipher: " + DoBenchmark(new StreamCipher()).ToString() + " Mbit/s");
            Console.WriteLine("RSA: " + DoBenchmark(rsa).ToString() + " Mbit/s");
            Console.WriteLine("CryptRand: " + DoBenchmark(CryptRand.Instance).ToString() + " Mbits/s");

        }


        public double DoBenchmark(SymmetricAlgorithm algo)
        {
            int size = 1024 * 1024 * 15; //15 MB

            DateTime start = DateTime.Now;

            byte[] buffer;
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;

            ICryptoTransform transform = algo.CreateEncryptor();


            int limit = size / transform.InputBlockSize;
            buffer = new byte[transform.InputBlockSize];

            for (int i = 0; i < limit; i++)
                transform.TransformBlock(buffer, 0, buffer.Length, buffer, 0);

            TimeSpan ende = DateTime.Now - start;

            return Math.Round(((size * 8) / ende.TotalSeconds) / 1000000, 2);
        }

        public double DoBenchmark(RandomNumberGenerator rng)
        {
            int size = 1024 * 1024 * 15; //15 MB
            int blockSize = 512;

            DateTime start = DateTime.Now;

            byte[] buffer;
            int limit = size / blockSize;
            buffer = new byte[blockSize];

            for (int i = 0; i < limit; i++)
                rng.GetBytes(buffer);

            TimeSpan ende = DateTime.Now - start;

            return Math.Round(((size * 8) / ende.TotalSeconds) / 1000000, 2);
        }

        public double DoBenchmark(RSAManaged algo)
        {
            int size = 1024 * 512 * 1; //0.5 MB
            int blockSize = (algo.KeySize >> 3) - 1;

            DateTime start = DateTime.Now;

            byte[] buffer;
            int limit = size / blockSize;
            buffer = new byte[blockSize];

            for (int i = 0; i < limit; i++)
                algo.EncryptValue(buffer);

            TimeSpan ende = DateTime.Now - start;


            return Math.Round(((size * 8) / ende.TotalSeconds) / 1000000, 2);

        }
    }
}
