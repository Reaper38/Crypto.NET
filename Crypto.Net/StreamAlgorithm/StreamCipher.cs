// StreamCipher.cs - A stream cipher using any SymmetricAlgorihtm (default: Twofish) in CFB, OFB or CTR mode

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

    public enum StreamMode
    {
        CFB, OFB, CTR
    }

    /// <summary>
    /// A stream cipher using any SymmetricAlgorihtm (default: Twofish) in CFB Mode
    /// It can encrypt/decrypt data of any length
    /// </summary>
    public class StreamCipher : SymmetricAlgorithm, IDisposable
    {
        private SymmetricAlgorithm algo;
        private ICryptoTransform transform;

        private byte[] iv, key;
        private byte[] keystreamEncrypt, keystreamDecrypt;
        private byte[] cipherInputEncrypt, cipherInputDecrypt;
        private int indexEncrypt, indexDecrypt;

        private CryptRand rng = CryptRand.Instance;
        private StreamMode mode = StreamMode.CFB;


        #region Properties
        /// <summary>
        /// The IV which was used for the initialization of the StreamCipher
        /// </summary>
        public new byte[] IV
        {
            get { return (byte[])iv.Clone(); }
        }

        /// <summary>
        /// They Key which is used
        /// </summary>
        public new byte[] Key
        {
            get { return (byte[])key.Clone(); }
        }

        /// <summary>
        /// Please use instead StreamMode
        /// </summary>
        [Obsolete("Please use instead StreamMode")]
        public override CipherMode Mode
        {
            get
            {
                switch (StreamMode)
                {
                    case StreamMode.OFB: return CipherMode.OFB; 
                    default: return CipherMode.CFB;
                }
            }
            set
            {
                switch (value)
                {
                    case CipherMode.OFB: StreamMode = StreamMode.OFB; break;
                    default: StreamMode = StreamMode.CFB; break;
                }
              
            }
        }
        
        /// <summary>
        /// The cipher mode
        /// </summary>
        public StreamMode StreamMode
        {
            get { return mode; }
            set
            {
                mode = value;

                if (mode == StreamMode.OFB)
                {
                    Buffer.BlockCopy(keystreamEncrypt, 0, cipherInputEncrypt, 0, cipherInputEncrypt.Length);
                    Buffer.BlockCopy(keystreamDecrypt, 0, cipherInputDecrypt, 0, cipherInputDecrypt.Length);
                }
            }

        }
        #endregion

        public StreamCipher()
            : this(new Twofish())
        {
            

        }

        public StreamCipher(SymmetricAlgorithm algorithm)
            : this(algorithm, algorithm.Key, algorithm.IV)
        {   
        }

        public StreamCipher(byte[] key, byte[] iv)
            : this(new Twofish(), key, iv)
        {
        }


        public StreamCipher(SymmetricAlgorithm algorithm, byte[] key, byte[] iv)
        {         
            this.algo = algorithm;
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;

            if (iv == null)
                iv = _GenerateIV();

            

            this.iv = (byte[])iv.Clone();
            this.key = (byte[])key.Clone();

            transform = algorithm.CreateEncryptor(this.key, this.iv);


            keystreamEncrypt = new byte[algo.BlockSize >> 3];
            keystreamDecrypt = new byte[algo.BlockSize >> 3];
            cipherInputEncrypt = new byte[algo.BlockSize >> 3];
            cipherInputDecrypt = new byte[algo.BlockSize >> 3];

            indexEncrypt = indexDecrypt = 0;

            
            //The IV is the first input of the symmetric algorithm
            Buffer.BlockCopy(iv, 0, cipherInputEncrypt, 0, iv.Length);
            Buffer.BlockCopy(iv, 0, cipherInputDecrypt, 0, iv.Length);
            


            transform.TransformBlock(cipherInputEncrypt, 0, cipherInputEncrypt.Length, keystreamEncrypt, 0);
            transform.TransformBlock(cipherInputDecrypt, 0, cipherInputDecrypt.Length, keystreamDecrypt, 0);

           
        }

        /// <summary>
        /// Encrypts input of any length in CFB-Mode
        /// </summary>      
        public virtual void Encrypt(byte[] input, byte[] output)
        {
            Encrypt(input, 0, input.Length, output, 0);
        }

        /// <summary>
        /// Encrypts input of any length in CFB-Mode
        /// </summary>  
        public virtual void Encrypt(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            if(outputOffset < 0)
                throw new ArgumentOutOfRangeException("outputOffset", "outputOffset has to be >0");

            if(inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "inputOffset has to be >0");

            if( inputLength == 0)
                return;

            if (inputLength > (output.Length - outputOffset))
                throw new ArgumentException("output is to small");


            //Using minmal methode calls for more speed           
            for (int i = 0, j = inputOffset; i < inputLength; i++, j++)
            {
                //Generates the next part of the keystream
                if (indexEncrypt >= keystreamEncrypt.Length)
                {
                    if (mode == StreamMode.CTR)
                        Increment(cipherInputEncrypt);

                    transform.TransformBlock(cipherInputEncrypt, 0, cipherInputEncrypt.Length, keystreamEncrypt, 0);
                    indexEncrypt = 0;

                    if (mode == StreamMode.OFB)
                        Buffer.BlockCopy(keystreamEncrypt, 0, cipherInputEncrypt, 0, cipherInputEncrypt.Length);
                }
      
                output[i + outputOffset] = (byte)(input[inputOffset + i] ^ keystreamEncrypt[indexEncrypt++]);

                if(mode == StreamMode.CFB)
                    cipherInputEncrypt[indexEncrypt - 1] = output[i + outputOffset];

            }
        }

        /// <summary>
        /// Decrypts input of any length in CFB-Mode
        /// </summary>  
        public virtual void Decrypt(byte[] input, byte[] output)
        {
            Decrypt(input, 0, input.Length, output, 0);
        }

        /// <summary>
        /// Decrypts input of any length in CFB-Mode
        /// </summary>  
        public virtual void Decrypt(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            if (outputOffset < 0)
                throw new ArgumentOutOfRangeException("outputOffset", "outputOffset has to be >0");

            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "inputOffset has to be >0");

            if (inputLength == 0)
                return;

            if (inputLength > (output.Length - outputOffset))
                throw new ArgumentException("output is to small");


            for (int i = 0, j = inputOffset; i < inputLength; i++, j++)
            {

                if (indexDecrypt >= keystreamDecrypt.Length)
                {
                    if (mode == StreamMode.CTR)
                        Increment(cipherInputDecrypt);

                    transform.TransformBlock(cipherInputDecrypt, 0, cipherInputDecrypt.Length, keystreamDecrypt, 0);
                    indexDecrypt = 0;

                    if (mode == StreamMode.OFB)
                        Buffer.BlockCopy(keystreamDecrypt, 0, cipherInputDecrypt, 0, cipherInputDecrypt.Length);
                }


                if (mode == StreamMode.CFB)
                    cipherInputDecrypt[indexDecrypt] = input[inputOffset + i];

                output[i + outputOffset] = (byte)(input[inputOffset + i] ^ keystreamDecrypt[indexDecrypt++]);
                
            }
        }
     


        /// <summary>
        /// Generates a random IV
        /// </summary> 
        protected virtual byte[] _GenerateIV()
        {
            byte[] result = new byte[algo.BlockSize >> 3];
            rng.GetBytes(result);

            return result;
        }


        //Increments a Value by 1
        private void Increment(byte[] data)
        {
            int i = data.Length-1;
            do
            {
                data[i--]++;
            } while (i >= 0 && data[i + 1] == 0);
        }


    
        #region IDisposable Member
        public new void Clear()
        {
            Dispose();
        }

        public void Dispose()
        {
            for (int i = 0; i < keystreamEncrypt.Length; i++)
                keystreamEncrypt[i] = 0x00;
            keystreamEncrypt = null;

            for (int i = 0; i < keystreamDecrypt.Length; i++)
                keystreamDecrypt[i] = 0x00;
            keystreamDecrypt = null;

            for (int i = 0; i < key.Length; i++)
                key[i] = 0x00;
            key = null;

            for (int i = 0; i < iv.Length; i++)
                iv[i] = 0x00;
            iv = null;

            algo.Clear();
            algo = null;
        }

        #endregion

        #region SymmetricAlgorithm Member
        public override ICryptoTransform CreateEncryptor()
        {
            return CreateEncryptor(algo.Key, algo.IV);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new StreamCipherTransform(algo, true, rgbKey, rgbIV);
        }



        public override ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(algo.Key, algo.IV);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new StreamCipherTransform(algo, false, rgbKey, rgbIV);
        }      

        public override void GenerateKey()
        {
            algo.GenerateKey();            
        }

        public override void GenerateIV()
        {
            algo.GenerateIV();
        }
        #endregion
    }



    /// <summary>
    /// An ICryptoTransform-Implementation of StreamCipher
    /// </summary>
    internal class StreamCipherTransform : ICryptoTransform
    {
        private StreamCipher streamCipher;
        private bool encryption;

        public StreamCipherTransform(SymmetricAlgorithm algorithm, bool encryption, byte[] key, byte[] iv)
        {
            streamCipher = new StreamCipher(algorithm, key, iv);
            this.encryption = encryption;
        }

        #region ICryptoTransform Member

        public bool CanReuseTransform
        {
            get { return false; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return false; }
        }

        public int InputBlockSize
        {
            get { return 16; }
        }

        public int OutputBlockSize
        {
            get { return 16; }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (encryption)
                streamCipher.Encrypt(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            else
                streamCipher.Decrypt(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);

            return (inputCount - inputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {    
            if ((inputCount - inputOffset) <= 0)
                return new byte[] { };

            byte[] output = new byte[inputCount - inputOffset];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);

            return output;
            
        }

        #endregion

        #region IDisposable Member

        public void Dispose()
        {
            streamCipher.Dispose();
            streamCipher = null;
            
        }

        #endregion

        
    }
}
