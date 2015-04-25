// SecureNetworkStream.cs - An encrypted network stream

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

using System.IO;
using System.Net;
using System.Net.Sockets;

using System.Security.Cryptography;

namespace CryptoNet
{
    /// <summary>
    /// An encrypted NetworkStream. It uses Diffie-Hellman for key-exchange 
    /// and Twofish in CFB-Mode.
    /// 
    /// The key-exchange happen automaticaly and for each session, another secret
    /// key is used.
    /// This class just protects your data, but it doesn't authenticate them.
    /// </summary>
    /// <example>
    /// TcpClient tcpClient = new TcpClient("192.168.0.1", 12345);
    /// NetworkStream stream = new SecureNetworkStream(tcpClient);  
    /// //Now you can use it like a normal Networkstream
    /// </example>   
    public sealed class SecureNetworkStream : NetworkStream
    {

        private StreamCipher streamCipherEncrypt, streamCipherDecrypt;
        private DiffieHellmanManaged dh;
        private CryptRand rng = CryptRand.Instance;


        private bool usingSharedKey = false;

        #region Constructor
        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>        
        public SecureNetworkStream(TcpClient client)
            : this(client.Client, new byte[0]) { }

        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>   
        public SecureNetworkStream(Socket socket)
            : this(socket, new byte[0]) { }

        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>   
        /// <param name="sharedKey">An optional pre-shared key. Each user has to know it</param>
        public SecureNetworkStream(TcpClient client, string sharedKey)
            : this(client, Encoding.UTF8.GetBytes(sharedKey)) { }

        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>   
        /// <param name="sharedKey">An optional pre-shared key. Each user has to know it</param>
        public SecureNetworkStream(TcpClient client, byte[] sharedKey)
            : this(client.Client, sharedKey) { }

        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>   
        /// <param name="sharedKey">An optional pre-shared key. Each user has to know it</param>
        public SecureNetworkStream(Socket socket, string sharedKey)
            : this(socket, Encoding.UTF8.GetBytes(sharedKey)) { }

        /// <summary>
        /// Provides an encrypted, and easy-to-use NetworkStream
        /// </summary>   
        /// <param name="sharedKey">An optional pre-shared key. Each user has to know it</param>
        public SecureNetworkStream(Socket socket, byte[] sharedKey)
            : base(socket)
        {

            if (sharedKey == null || sharedKey.Length == 0)
                usingSharedKey = false;
            else
                usingSharedKey = true;

            dh = new DiffieHellmanManaged();


            if (!socket.Connected)
                throw new IOException("Socket is not connected");

            if (!base.CanRead || !base.CanWrite)
                throw new IOException("Can't read or write");

            Handshake(sharedKey);
        }

        
        
        #endregion

        #region Input/Output
        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
        {
            streamCipherEncrypt.Encrypt(buffer, offset, size, buffer, offset);
            return base.BeginWrite(buffer, offset, size, callback, state);            
        }

        public override void Write(byte[] buffer, int offset, int size)
        {
            streamCipherEncrypt.Encrypt(buffer, offset, size, buffer, offset);

            base.Write(buffer, offset, size);
        }


        #region BeginRead
        // BeginRead is a little bit tricky, because we need to know 
        // how many had been read from the stream.
        // To get this information, we have to call EndRead,
        // but if we do this in BeginRead, we have just a synchronous read.
        // So we have to redirect the callback to an internal method 'BeginReadCallback'.
        // This methode must then call EndRead to get the length an then it has to call the
        // orginal callback.   
        public override IAsyncResult BeginRead(byte[] buffer, int offset, int size, AsyncCallback callback, object state)
        {
            object[] tmp = new object[] { callback, state, buffer, offset, size }; 

            IAsyncResult res = base.BeginRead(buffer, offset, size, new AsyncCallback(BeginReadCallback), tmp);
            return res;
        }

        // This class is used from BeginReadCallback.
        // We need a class which implements the IAsyncResult-Interface
        // because we need to change the AsyncState to the orginal state
        // which was committed to BeginRead-Methode 
        private class SecureNetworkAsyncResult : IAsyncResult
        {
            private IAsyncResult ar;
            private object state;
            private int length;

            internal int Length { get { return length; } }

            public SecureNetworkAsyncResult(IAsyncResult ar, object state, int length)
            {
                this.ar = ar;
                this.state = state;
                this.length = length;
            }

            #region IAsyncResult Member

            public object AsyncState
            {
                get { return state; }
            }

            public System.Threading.WaitHandle AsyncWaitHandle
            {
                get { return ar.AsyncWaitHandle; }
            }

            public bool CompletedSynchronously
            {
                get { return ar.CompletedSynchronously; }
            }

            public bool IsCompleted
            {
                get { return ar.IsCompleted; }
            }
            #endregion
        }

        // This methode is the destination of the asynchronus callback.
        // Its decrypts the data and then calls the orginal callback
        private void BeginReadCallback(IAsyncResult ar)
        {
            AsyncCallback orgCallback = (AsyncCallback)((object[])ar.AsyncState)[0];
            object state = ((object[])ar.AsyncState)[1];
            byte[] buffer = (byte[])((object[])ar.AsyncState)[2];
            int offset = (int)((object[])ar.AsyncState)[3];
            int size = (int)((object[])ar.AsyncState)[4];
            int length = base.EndRead(ar);


            SecureNetworkAsyncResult result = new SecureNetworkAsyncResult(ar, state, length);
            

            if (length > 0)
                streamCipherDecrypt.Decrypt(buffer, offset, length, buffer, offset);

            orgCallback(result);
        }

        // Because BeginReadCallback already calls EndRead, a second call
        // of this methode would produce an exception.
        // If the asyncResult has the type of 'SecureNetworkAsyncResult'
        // it returns the length, which is diposited in the object
        public override int EndRead(IAsyncResult asyncResult)
        {
            if (asyncResult is SecureNetworkAsyncResult)
                return ((SecureNetworkAsyncResult)asyncResult).Length;
            else
                return base.EndRead(asyncResult);
        }
        #endregion

        public override int Read(byte[] buffer, int offset, int size)
        {
            int length = base.Read(buffer, offset, size);

            
            if (length <= 0)
                return length;

            streamCipherDecrypt.Decrypt(buffer, offset, length, buffer, offset);

            return length;
        }

      
        #endregion

        #region Handshake
        //Handshake for generating a random key and a random iv for en/decryption
        private void Handshake(byte[] sharedKey)
        {   
            byte[] keyEx, randI, randYou, x, tmp,  header, keyChecksum;

                        
            //Generate Diffie-Hellman KexExchange data and a random 128-bit value
            keyEx = dh.CreateKeyExchange();
            randI = new byte[16];
            randYou = new byte[randI.Length];
            rng.GetBytes(randI);

            //1. Step: Send Header
            //   Byte   Usage
            //      1   Using MAC
            //      2   Using SharedKey
            //   3-18   Random value
            // 19-146   KeyExchange Data
            header = new byte[1 + 128 + randI.Length];           
            
            header[0] = (byte)((usingSharedKey) ? 1 : 0);

            Buffer.BlockCopy(randI, 0, header, 1, randI.Length);
            Buffer.BlockCopy(keyEx, 0, header, (header.Length - keyEx.Length), keyEx.Length);
            base.Write(header, 0, header.Length);


            Array.Clear(header, 0, header.Length);
            Array.Clear(keyEx, 0, keyEx.Length);

            //2. Step: Receive Header           
            base.Read(header, 0, header.Length);

            Buffer.BlockCopy(header, 1, randYou, 0, randYou.Length);
            Buffer.BlockCopy(header, randYou.Length+1, keyEx, 0, keyEx.Length);
              
            //If the other want a MAC, then use a MAC            

            //Just one uses a pre-shared key => Connection Close
            if ((usingSharedKey && header[0] == 0) || (!usingSharedKey && header[0] == 1))
                throw new CryptographicException("Just one uses a pre-shared key");
           



            //Secret key
            x = dh.DecryptKeyExchange(keyEx);
            keyChecksum = GenerateKeys(x, randI, randYou, sharedKey);                      

            //Clean data             
            Array.Clear(keyEx, 0, keyEx.Length);
            Array.Clear(randI, 0, randI.Length);
            Array.Clear(randYou, 0, randYou.Length);
            Array.Clear(x, 0, x.Length);           
            Array.Clear(header, 0, header.Length);
            header = keyEx = randI = randYou =  x  = null;
            dh.Clear();
            dh = null;

            //5. Step: Send checksum of the keys
            base.Write(keyChecksum, 0, keyChecksum.Length);

            //6. Step: Read checksum of the keys and compare it with own checksum
            tmp = new byte[keyChecksum.Length];
            base.Read(tmp, 0, tmp.Length);

            for (int i = 0; i < keyChecksum.Length; i++)
                if (keyChecksum[i] != tmp[i])
                    throw new CryptographicException("The key checksums from server and client are different");


            Array.Clear(keyChecksum, 0, keyChecksum.Length);
            Array.Clear(tmp, 0, tmp.Length);

            tmp = keyChecksum = null;

           
        }

        private byte[] GenerateKeys(byte[] x, byte[] randI, byte[] randYou, byte[] sharedKey)
        {
            byte[] h1, h2, keyEncrypt, keyDecrypt, tmp, ivEncrypt, ivDecrypt, checksum;

            if (!usingSharedKey)
                sharedKey = new byte[0];

            SHA256 sha256 = new SHA256Managed();
            MD5 md5 = MD5.Create();

            h1 = md5.ComputeHash(randI);
            h2 = md5.ComputeHash(randYou);


            //Create Keys and IVs

            //Encryption key = SHA256(x || randI || MD5(randYou) || sharedKey)
            tmp = new byte[x.Length + randI.Length + h2.Length + sharedKey.Length];

            Buffer.BlockCopy(x, 0, tmp, 0, x.Length);
            Buffer.BlockCopy(randI, 0, tmp, x.Length, randI.Length);
            Buffer.BlockCopy(h2, 0, tmp, (x.Length + randI.Length), h1.Length);
            Buffer.BlockCopy(sharedKey, 0, tmp, (x.Length + randI.Length + h2.Length), sharedKey.Length);

            keyEncrypt = sha256.ComputeHash(tmp);


            //Decryption key = SHA256(x || randYou || MD5(randI) || sharedKey)
            tmp = new byte[x.Length + randYou.Length + h1.Length + sharedKey.Length];

            Buffer.BlockCopy(x, 0, tmp, 0, x.Length);
            Buffer.BlockCopy(randYou, 0, tmp, x.Length, randYou.Length);
            Buffer.BlockCopy(h1, 0, tmp, (x.Length + randYou.Length), h1.Length);
            Buffer.BlockCopy(sharedKey, 0, tmp, (x.Length + randYou.Length + h1.Length), sharedKey.Length);

            keyDecrypt = sha256.ComputeHash(tmp);


            //IV encryption = MD5 ( randI || MD5(randYou))
            Array.Clear(tmp, 0, tmp.Length);

            tmp = new byte[randI.Length + h2.Length];
            Buffer.BlockCopy(randI, 0, tmp, 0, randI.Length);
            Buffer.BlockCopy(h2, 0, tmp, randI.Length, h2.Length);

            ivEncrypt = md5.ComputeHash(tmp);

            //IV decryption = MD5 ( randYou || MD5(randI))
            Buffer.BlockCopy(randYou, 0, tmp, 0, randYou.Length);
            Buffer.BlockCopy(h1, 0, tmp, randYou.Length, h1.Length);

            ivDecrypt = md5.ComputeHash(tmp);


            //Initialize StreamCiphers
            streamCipherEncrypt = new StreamCipher(keyEncrypt, ivEncrypt);
            streamCipherDecrypt = new StreamCipher(keyDecrypt, ivDecrypt);


            //Checksum Keys (keyEncrypt ^ keyDecrypt)
            tmp = new byte[keyEncrypt.Length];
            Buffer.BlockCopy(keyEncrypt, 0, tmp, 0, keyEncrypt.Length);

            for (int i = 0; i < tmp.Length; i++)
                tmp[i] ^= keyDecrypt[i];

            checksum = md5.ComputeHash(tmp);

            //Clear Data
            Array.Clear(h1, 0, h1.Length);
            Array.Clear(h2, 0, h2.Length);
            Array.Clear(keyEncrypt, 0, keyEncrypt.Length);
            Array.Clear(keyDecrypt, 0, keyDecrypt.Length);
            Array.Clear(tmp, 0, tmp.Length);
            Array.Clear(ivEncrypt, 0, ivEncrypt.Length);
            Array.Clear(ivDecrypt, 0, ivDecrypt.Length);

            h1 = h2 = keyEncrypt = keyDecrypt = tmp = ivEncrypt = ivDecrypt;

            return checksum;

        }

        #endregion

        #region Dispose
        protected override void Dispose(bool disposing)
        {
            streamCipherEncrypt.Dispose();
            streamCipherDecrypt.Dispose();

            base.Dispose(disposing);
        }
        #endregion

    }
}
