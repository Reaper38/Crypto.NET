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

using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace CryptoNet_Examples
{
    class SecureNetworkStreamExample
    {
        public SecureNetworkStreamExample()
        {
           

            Thread server = new Thread(new ThreadStart(Server));
            server.IsBackground = true;
            server.Start();

            Thread client = new Thread(new ThreadStart(Client));
            client.IsBackground = true;
            client.Start();

            Thread.Sleep(3000);

        }



       
        /// <summary>
        /// This is our networkserver, which listen on port 8888 for connections
        /// </summary>
        public void Server()
        {
            byte[] buffer = new byte[256];

            TcpListener listener = new TcpListener(IPAddress.Any, 8888);
            listener.Start();
            TcpClient tcpClient = listener.AcceptTcpClient();
            NetworkStream stream = new SecureNetworkStream(tcpClient);


            int read = stream.Read(buffer, 0, buffer.Length);
           
            string s = Encoding.UTF8.GetString(buffer, 0, read);
            Console.WriteLine("Message from client: " + s);
            
            tcpClient.Close();
            listener.Stop();


            

        }

     

        /// <summary>
        /// Our client connecting to our server.
        /// </summary>
        public void Client()
        {
            TcpClient tcpClient = new TcpClient("localhost", 8888);
            NetworkStream stream = new SecureNetworkStream(tcpClient);
            byte[] buffer = Encoding.UTF8.GetBytes("Hello World from Client");      

       
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();

            
            Thread.Sleep(5000);
        }
    }
}
