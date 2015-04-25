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

namespace CryptoNet_Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Select:");
            Console.WriteLine("1) Benchmark");
            Console.WriteLine("2) DiffieHellman");
            Console.WriteLine("3) StringCrypt");
            Console.WriteLine("4) SecureNetworkStream");
      
            string key = Console.ReadLine();
            switch (key)
            {
                case "1": new Benchmark(); break;
                case "2": new DiffieHellmanExample(); break;
                case "3": new StringCryptExample(); break;
                case "4": new SecureNetworkStreamExample(); break;
                default: Console.WriteLine("Unknown selection"); break;
            }


            Console.WriteLine("\n\nPress any key to exit...");
            Console.ReadKey();

        }
    }
}
