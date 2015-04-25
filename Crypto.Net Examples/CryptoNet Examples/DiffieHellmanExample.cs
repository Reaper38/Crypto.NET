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
using CryptoNet;

namespace CryptoNet_Examples
{
    public class DiffieHellmanExample
    {
        public DiffieHellmanExample()
        {

            DiffieHellmanManaged alice = new DiffieHellmanManaged();
            DiffieHellmanManaged bob = new DiffieHellmanManaged();


            byte[] exchange1 = alice.CreateKeyExchange();

            //Alice sends exhange1 to bob            
            byte[] exchange2 = bob.CreateKeyExchange();
            byte[] bobKey = bob.DecryptKeyExchange(exchange1);

            //Bob sends exchange2 to alice
            byte[] aliceKey = alice.DecryptKeyExchange(exchange2);


            //bobKey and aliceKey are equal
            Console.WriteLine("Bob's key:");
            for (int i = 0; i < bobKey.Length; i++)
                Console.Write("{0:X} ", bobKey[i]);


            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Alice's key:");
            for (int i = 0; i < aliceKey.Length; i++)
                Console.Write("{0:X} ", aliceKey[i]);
        }
    }
}
