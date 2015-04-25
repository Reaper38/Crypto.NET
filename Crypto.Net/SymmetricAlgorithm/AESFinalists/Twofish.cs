// Twofish.cs - An optimized implementation in C# of the Twofish cipher

//============================================================================
// CryptoNet - A cryptography library for C#
// 
// Copyright (C) 2007  Nils Reimers (www.php-einfach.de)
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
//=============================================================================

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;




namespace CryptoNet
{
    /*
     * Twofish is an AES candidate algorithm. It is a balanced 128-bit Feistel
     * cipher, consisting of 16 rounds. In each round, a 64-bit S-box value is
     * computed from 64 bits of the block, and this value is xored into the other
     * half of the block. The two half-blocks are then exchanged, and the next
     * round begins. Before the first round, all input bits are xored with key-
     * dependent "whitening" subkeys, and after the final round the output bits
     * are xored with other key-dependent whitening subkeys; these subkeys are
     * not used anywhere else in the algorithm.<p>
     *
     * Twofish was submitted by Bruce Schneier, Doug Whiting, John Kelsey, Chris
     * Hall and David Wagner.
     *
     * Reference:
     *  TWOFISH2.C -- Optimized C API calls for TWOFISH AES submission,
     *  Version 1.00, April 1998, by Doug Whiting.
     * 
     * Twofish is unpatented and license-free, and is available free for all uses.
     */

    /// <summary>
    /// Blockcipher Twofish (one of the 5 AES finalists) 
    /// </summary>
    public class Twofish : SymmetricAlgorithm
    {
        CryptRand rng = CryptRand.Instance;

        public Twofish()
            : base()
        {                        
            BlockSizeValue = 128;
            KeySizeValue = 256;
            ModeValue = CipherMode.CBC;

            //LegalBlockSizes = new KeySizes[1];
            base.LegalBlockSizesValue = new KeySizes[1];
            base.LegalBlockSizesValue[0] = new KeySizes(128, 128, 128);

            LegalKeySizesValue = new KeySizes[1];
            LegalKeySizesValue[0] = new KeySizes(128, 256, 64); 
        }
      

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new TwofishTransform(this, false, rgbKey, rgbIV);            
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new TwofishTransform(this, true, rgbKey, rgbIV);           
        }

        public override void GenerateIV()
        {
            byte[] iv = new byte[BlockSizeValue >> 3];
            rng.GetBytes(iv);

            IVValue = iv;
        }

        public override void GenerateKey()
        {
            byte[] key = new byte[KeySize >> 3];
            rng.GetBytes(key);

            KeyValue = key;
        }
    }


    #region Twofish Transform
    /* 
     * A highly optimized (~7 times faster) of the Twofish cipher  
     */
    internal class  TwofishTransform : SymmetricTransform
    {
        private bool encryption;

        protected uint[] subKeys;
        protected uint[] sBox;

        public TwofishTransform(Twofish algo, bool encryption, byte[] key, byte[] iv)
            : base(algo, encryption, iv)
        {

            if ((iv != null) && (iv.Length != (algo.BlockSize >> 3))) 
                throw new CryptographicException("IV length is invalid (" + iv.Length + " bytes), it should be " + (algo.BlockSize >> 3) + " bytes long.");
           
            if (key != null && key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new CryptographicException("key has an invalid length. Valid lengths are 16, 24 and 32 byte");


            this.encryption = encryption;
            MakeKey(key);
            
        }

        protected override void ECB(byte[] input, byte[] output)
        {
            if (encryption)
                BlockEncrypt(input, output);
            else
                BlockDecrypt(input, output);
        }


        #region Constants
        private const uint BLOCK_SIZE = 16; // bytes in a data-block
        private const uint ROUNDS = 16;
        private const uint MAX_ROUNDS = 16; // max # rounds (for allocating subkeys)
       
        /* Subkey array indices */      
        private const uint ROUND_SUBKEYS = 4 + BLOCK_SIZE / 4; // 2*(# rounds)
        private const uint TOTAL_SUBKEYS = ROUND_SUBKEYS + 2 * MAX_ROUNDS;

        private const uint SK_STEP = 0x02020202;
        private const uint SK_BUMP = 0x01010101;
        private const int SK_ROTL = 9;


        private const uint P_00 = 1;
        private const uint P_01 = 0;
        private const uint P_02 = 0;
        private const uint P_03 = P_01 ^ 1;
        private const uint P_04 = 1;

        private const uint P_10 = 0;
        private const uint P_11 = 0;
        private const uint P_12 = 1;
        private const uint P_13 = P_11 ^ 1;
        private const uint P_14 = 0;

        private const uint P_20 = 1;
        private const uint P_21 = 1;
        private const uint P_22 = 0;
        private const uint P_23 = P_21 ^ 1;
        private const uint P_24 = 0;

        private const uint P_30 = 0;
        private const uint P_31 = 1;
        private const uint P_32 = 1;
        private const uint P_33 = P_31 ^ 1;
        private const uint P_34 = 1;
        #endregion

        #region P-Box

        /** Fixed 8x8 permutation S-boxes */
        protected static byte[][] P = new byte[][] {
        new byte[] {  // p0
         (byte) 0xA9, (byte) 0x67, (byte) 0xB3, (byte) 0xE8,
         (byte) 0x04, (byte) 0xFD, (byte) 0xA3, (byte) 0x76,
         (byte) 0x9A, (byte) 0x92, (byte) 0x80, (byte) 0x78,
         (byte) 0xE4, (byte) 0xDD, (byte) 0xD1, (byte) 0x38,
         (byte) 0x0D, (byte) 0xC6, (byte) 0x35, (byte) 0x98,
         (byte) 0x18, (byte) 0xF7, (byte) 0xEC, (byte) 0x6C,
         (byte) 0x43, (byte) 0x75, (byte) 0x37, (byte) 0x26,
         (byte) 0xFA, (byte) 0x13, (byte) 0x94, (byte) 0x48,
         (byte) 0xF2, (byte) 0xD0, (byte) 0x8B, (byte) 0x30,
         (byte) 0x84, (byte) 0x54, (byte) 0xDF, (byte) 0x23,
         (byte) 0x19, (byte) 0x5B, (byte) 0x3D, (byte) 0x59,
         (byte) 0xF3, (byte) 0xAE, (byte) 0xA2, (byte) 0x82,
         (byte) 0x63, (byte) 0x01, (byte) 0x83, (byte) 0x2E,
         (byte) 0xD9, (byte) 0x51, (byte) 0x9B, (byte) 0x7C,
         (byte) 0xA6, (byte) 0xEB, (byte) 0xA5, (byte) 0xBE,
         (byte) 0x16, (byte) 0x0C, (byte) 0xE3, (byte) 0x61,
         (byte) 0xC0, (byte) 0x8C, (byte) 0x3A, (byte) 0xF5,
         (byte) 0x73, (byte) 0x2C, (byte) 0x25, (byte) 0x0B,
         (byte) 0xBB, (byte) 0x4E, (byte) 0x89, (byte) 0x6B,
         (byte) 0x53, (byte) 0x6A, (byte) 0xB4, (byte) 0xF1,
         (byte) 0xE1, (byte) 0xE6, (byte) 0xBD, (byte) 0x45,
         (byte) 0xE2, (byte) 0xF4, (byte) 0xB6, (byte) 0x66,
         (byte) 0xCC, (byte) 0x95, (byte) 0x03, (byte) 0x56,
         (byte) 0xD4, (byte) 0x1C, (byte) 0x1E, (byte) 0xD7,
         (byte) 0xFB, (byte) 0xC3, (byte) 0x8E, (byte) 0xB5,
         (byte) 0xE9, (byte) 0xCF, (byte) 0xBF, (byte) 0xBA,
         (byte) 0xEA, (byte) 0x77, (byte) 0x39, (byte) 0xAF,
         (byte) 0x33, (byte) 0xC9, (byte) 0x62, (byte) 0x71,
         (byte) 0x81, (byte) 0x79, (byte) 0x09, (byte) 0xAD,
         (byte) 0x24, (byte) 0xCD, (byte) 0xF9, (byte) 0xD8,
         (byte) 0xE5, (byte) 0xC5, (byte) 0xB9, (byte) 0x4D,
         (byte) 0x44, (byte) 0x08, (byte) 0x86, (byte) 0xE7,
         (byte) 0xA1, (byte) 0x1D, (byte) 0xAA, (byte) 0xED,
         (byte) 0x06, (byte) 0x70, (byte) 0xB2, (byte) 0xD2,
         (byte) 0x41, (byte) 0x7B, (byte) 0xA0, (byte) 0x11,
         (byte) 0x31, (byte) 0xC2, (byte) 0x27, (byte) 0x90,
         (byte) 0x20, (byte) 0xF6, (byte) 0x60, (byte) 0xFF,
         (byte) 0x96, (byte) 0x5C, (byte) 0xB1, (byte) 0xAB,
         (byte) 0x9E, (byte) 0x9C, (byte) 0x52, (byte) 0x1B,
         (byte) 0x5F, (byte) 0x93, (byte) 0x0A, (byte) 0xEF,
         (byte) 0x91, (byte) 0x85, (byte) 0x49, (byte) 0xEE,
         (byte) 0x2D, (byte) 0x4F, (byte) 0x8F, (byte) 0x3B,
         (byte) 0x47, (byte) 0x87, (byte) 0x6D, (byte) 0x46,
         (byte) 0xD6, (byte) 0x3E, (byte) 0x69, (byte) 0x64,
         (byte) 0x2A, (byte) 0xCE, (byte) 0xCB, (byte) 0x2F,
         (byte) 0xFC, (byte) 0x97, (byte) 0x05, (byte) 0x7A,
         (byte) 0xAC, (byte) 0x7F, (byte) 0xD5, (byte) 0x1A,
         (byte) 0x4B, (byte) 0x0E, (byte) 0xA7, (byte) 0x5A,
         (byte) 0x28, (byte) 0x14, (byte) 0x3F, (byte) 0x29,
         (byte) 0x88, (byte) 0x3C, (byte) 0x4C, (byte) 0x02,
         (byte) 0xB8, (byte) 0xDA, (byte) 0xB0, (byte) 0x17,
         (byte) 0x55, (byte) 0x1F, (byte) 0x8A, (byte) 0x7D,
         (byte) 0x57, (byte) 0xC7, (byte) 0x8D, (byte) 0x74,
         (byte) 0xB7, (byte) 0xC4, (byte) 0x9F, (byte) 0x72,
         (byte) 0x7E, (byte) 0x15, (byte) 0x22, (byte) 0x12,
         (byte) 0x58, (byte) 0x07, (byte) 0x99, (byte) 0x34,
         (byte) 0x6E, (byte) 0x50, (byte) 0xDE, (byte) 0x68,
         (byte) 0x65, (byte) 0xBC, (byte) 0xDB, (byte) 0xF8,
         (byte) 0xC8, (byte) 0xA8, (byte) 0x2B, (byte) 0x40,
         (byte) 0xDC, (byte) 0xFE, (byte) 0x32, (byte) 0xA4,
         (byte) 0xCA, (byte) 0x10, (byte) 0x21, (byte) 0xF0,
         (byte) 0xD3, (byte) 0x5D, (byte) 0x0F, (byte) 0x00,
         (byte) 0x6F, (byte) 0x9D, (byte) 0x36, (byte) 0x42,
         (byte) 0x4A, (byte) 0x5E, (byte) 0xC1, (byte) 0xE0
      }, 
      new byte[] {  // p1
         (byte) 0x75, (byte) 0xF3, (byte) 0xC6, (byte) 0xF4,
         (byte) 0xDB, (byte) 0x7B, (byte) 0xFB, (byte) 0xC8,
         (byte) 0x4A, (byte) 0xD3, (byte) 0xE6, (byte) 0x6B,
         (byte) 0x45, (byte) 0x7D, (byte) 0xE8, (byte) 0x4B,
         (byte) 0xD6, (byte) 0x32, (byte) 0xD8, (byte) 0xFD,
         (byte) 0x37, (byte) 0x71, (byte) 0xF1, (byte) 0xE1,
         (byte) 0x30, (byte) 0x0F, (byte) 0xF8, (byte) 0x1B,
         (byte) 0x87, (byte) 0xFA, (byte) 0x06, (byte) 0x3F,
         (byte) 0x5E, (byte) 0xBA, (byte) 0xAE, (byte) 0x5B,
         (byte) 0x8A, (byte) 0x00, (byte) 0xBC, (byte) 0x9D,
         (byte) 0x6D, (byte) 0xC1, (byte) 0xB1, (byte) 0x0E,
         (byte) 0x80, (byte) 0x5D, (byte) 0xD2, (byte) 0xD5,
         (byte) 0xA0, (byte) 0x84, (byte) 0x07, (byte) 0x14,
         (byte) 0xB5, (byte) 0x90, (byte) 0x2C, (byte) 0xA3,
         (byte) 0xB2, (byte) 0x73, (byte) 0x4C, (byte) 0x54,
         (byte) 0x92, (byte) 0x74, (byte) 0x36, (byte) 0x51,
         (byte) 0x38, (byte) 0xB0, (byte) 0xBD, (byte) 0x5A,
         (byte) 0xFC, (byte) 0x60, (byte) 0x62, (byte) 0x96,
         (byte) 0x6C, (byte) 0x42, (byte) 0xF7, (byte) 0x10,
         (byte) 0x7C, (byte) 0x28, (byte) 0x27, (byte) 0x8C,
         (byte) 0x13, (byte) 0x95, (byte) 0x9C, (byte) 0xC7,
         (byte) 0x24, (byte) 0x46, (byte) 0x3B, (byte) 0x70,
         (byte) 0xCA, (byte) 0xE3, (byte) 0x85, (byte) 0xCB,
         (byte) 0x11, (byte) 0xD0, (byte) 0x93, (byte) 0xB8,
         (byte) 0xA6, (byte) 0x83, (byte) 0x20, (byte) 0xFF,
         (byte) 0x9F, (byte) 0x77, (byte) 0xC3, (byte) 0xCC,
         (byte) 0x03, (byte) 0x6F, (byte) 0x08, (byte) 0xBF,
         (byte) 0x40, (byte) 0xE7, (byte) 0x2B, (byte) 0xE2,
         (byte) 0x79, (byte) 0x0C, (byte) 0xAA, (byte) 0x82,
         (byte) 0x41, (byte) 0x3A, (byte) 0xEA, (byte) 0xB9,
         (byte) 0xE4, (byte) 0x9A, (byte) 0xA4, (byte) 0x97,
         (byte) 0x7E, (byte) 0xDA, (byte) 0x7A, (byte) 0x17,
         (byte) 0x66, (byte) 0x94, (byte) 0xA1, (byte) 0x1D,
         (byte) 0x3D, (byte) 0xF0, (byte) 0xDE, (byte) 0xB3,
         (byte) 0x0B, (byte) 0x72, (byte) 0xA7, (byte) 0x1C,
         (byte) 0xEF, (byte) 0xD1, (byte) 0x53, (byte) 0x3E,
         (byte) 0x8F, (byte) 0x33, (byte) 0x26, (byte) 0x5F,
         (byte) 0xEC, (byte) 0x76, (byte) 0x2A, (byte) 0x49,
         (byte) 0x81, (byte) 0x88, (byte) 0xEE, (byte) 0x21,
         (byte) 0xC4, (byte) 0x1A, (byte) 0xEB, (byte) 0xD9,
         (byte) 0xC5, (byte) 0x39, (byte) 0x99, (byte) 0xCD,
         (byte) 0xAD, (byte) 0x31, (byte) 0x8B, (byte) 0x01,
         (byte) 0x18, (byte) 0x23, (byte) 0xDD, (byte) 0x1F,
         (byte) 0x4E, (byte) 0x2D, (byte) 0xF9, (byte) 0x48,
         (byte) 0x4F, (byte) 0xF2, (byte) 0x65, (byte) 0x8E,
         (byte) 0x78, (byte) 0x5C, (byte) 0x58, (byte) 0x19,
         (byte) 0x8D, (byte) 0xE5, (byte) 0x98, (byte) 0x57,
         (byte) 0x67, (byte) 0x7F, (byte) 0x05, (byte) 0x64,
         (byte) 0xAF, (byte) 0x63, (byte) 0xB6, (byte) 0xFE,
         (byte) 0xF5, (byte) 0xB7, (byte) 0x3C, (byte) 0xA5,
         (byte) 0xCE, (byte) 0xE9, (byte) 0x68, (byte) 0x44,
         (byte) 0xE0, (byte) 0x4D, (byte) 0x43, (byte) 0x69,
         (byte) 0x29, (byte) 0x2E, (byte) 0xAC, (byte) 0x15,
         (byte) 0x59, (byte) 0xA8, (byte) 0x0A, (byte) 0x9E,
         (byte) 0x6E, (byte) 0x47, (byte) 0xDF, (byte) 0x34,
         (byte) 0x35, (byte) 0x6A, (byte) 0xCF, (byte) 0xDC,
         (byte) 0x22, (byte) 0xC9, (byte) 0xC0, (byte) 0x9B,
         (byte) 0x89, (byte) 0xD4, (byte) 0xED, (byte) 0xAB,
         (byte) 0x12, (byte) 0xA2, (byte) 0x0D, (byte) 0x52,
         (byte) 0xBB, (byte) 0x02, (byte) 0x2F, (byte) 0xA9,
         (byte) 0xD7, (byte) 0x61, (byte) 0x1E, (byte) 0xB4,
         (byte) 0x50, (byte) 0x04, (byte) 0xF6, (byte) 0xC2,
         (byte) 0x16, (byte) 0x25, (byte) 0x86, (byte) 0x56,
         (byte) 0x55, (byte) 0x09, (byte) 0xBE, (byte) 0x91
      }
        };


        #endregion

        #region MDS
        /** Primitive polynomial for GF(256) */
        private const uint GF256_FDBK =   0x169;
        private const uint GF256_FDBK_2 = 0x169 / 2;
        private const uint GF256_FDBK_4 = 0x169 / 4;
        private const uint RS_GF_FDBK = 0x14D; // field generator

        protected static uint[,] MDS; // blank final

        protected static void PrecomputeMDS()
        {
          

            MDS = new uint[4, 256];

            uint[] m1 = new uint[2];
            uint[] mX = new uint[2];
            uint[] mY = new uint[2];
            uint j = 0;

            for (uint i = 0; i < 256; i++)
            {
                j = (uint)(P[0][i] & 0xFF); // compute all the matrix elements
                m1[0] = j;
                mX[0] = Mx_X(j) & 0xFF;
                mY[0] = Mx_Y(j) & 0xFF;

                j = (uint)(P[1][i] & 0xFF);
                m1[1] = j;
                mX[1] = Mx_X(j) & 0xFF;
                mY[1] = Mx_Y(j) & 0xFF;

                MDS[0,i] = m1[P_00] << 0 | // fill matrix w/ above elements
                            mX[P_00] << 8 |
                            mY[P_00] << 16 |
                            mY[P_00] << 24;
                MDS[1,i] = mY[P_10] << 0 |
                            mY[P_10] << 8 |
                            mX[P_10] << 16 |
                            m1[P_10] << 24;
                MDS[2,i] = mX[P_20] << 0 |
                            mY[P_20] << 8 |
                            m1[P_20] << 16 |
                            mY[P_20] << 24;
                MDS[3,i] = mX[P_30] << 0 |
                            m1[P_30] << 8 |
                            mY[P_30] << 16 |
                            mX[P_30] << 24;
            }

           
        }

        
        protected static uint Mx_X(uint x) { return x ^ LFSR2(x); }           
        protected static uint Mx_Y(uint x) { return x ^ LFSR1(x) ^ LFSR2(x); }

        private static uint LFSR1(uint x)
        {
            return (x >> 1) ^ ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
        }

        private static uint LFSR2(uint x)
        {
            return (x >> 2) ^
                  ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^
                  ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
        }
        #endregion

        #region KeySetup
        protected void MakeKey(byte[] key)
        {
            
            if(MDS == null)
              PrecomputeMDS();

            uint length = (uint)key.Length;


            uint k64Cnt = length / 8;
            uint subkeyCnt = ROUND_SUBKEYS + 2*ROUNDS;
            uint[] k32e = new uint[4]; // even 32-bit entities
            uint[] k32o = new uint[4]; // odd 32-bit entities
            uint[] sBoxKey = new uint[4];
            //
            // split user key material into even and odd 32-bit entities and
            // compute S-box keys using (12, 8) Reed-Solomon code over GF(256)
            //
            uint i, j, offset = 0;
            for (i = 0, j = k64Cnt - 1; i < 4 && offset < length; i++, j--)
            {
                k32e[i] = (uint)((key[offset++] & 0xFF)) |
                          (uint)((key[offset++] & 0xFF)) << 8 |
                          (uint)((key[offset++] & 0xFF)) << 16 |
                          (uint)((key[offset++] & 0xFF)) << 24;
                k32o[i] = (uint)((key[offset++] & 0xFF)) |
                          (uint)((key[offset++] & 0xFF)) << 8 |
                          (uint)((key[offset++] & 0xFF)) << 16 |
                          (uint)((key[offset++] & 0xFF)) << 24;
                sBoxKey[j] = RS_MDS_Encode(k32e[i], k32o[i]); // reverse order
            }
            // compute the round decryption subkeys for PHT. these same subkeys
            // will be used in encryption but will be applied in reverse order.
            uint q;
            uint A, B;
            subKeys = new uint[subkeyCnt];
            for (i = 0, q = 0; i < subkeyCnt / 2; i++, q += SK_STEP)
            {

                A = F32(k64Cnt, q, k32e); // A uses even key entities
                B = F32(k64Cnt, q + SK_BUMP, k32o); // B uses odd  key entities
                B = B << 8 | B >> 24;
                A += B;
                subKeys[2 * i] = A;               // combine with a PHT
                A += B;
                subKeys[2 * i + 1] = A << SK_ROTL | A >> (32 - SK_ROTL);
            }

        


            //
            // fully expand the table for speed
            //
            uint k0 = sBoxKey[0];
            uint k1 = sBoxKey[1];
            uint k2 = sBoxKey[2];
            uint k3 = sBoxKey[3];
            uint b0x, b1x, b2x, b3x;
            sBox = new uint[4 * 256];
            bool next = false;
            for (i = 0; i < 256; i++)
            {
                b0x = b1x = b2x = b3x = i;
                next = false;
                if ((k64Cnt & 3) == 1)
                {

                    sBox[2 * i] = MDS[0, (P[P_01][b0x] & 0xFF) ^ (k0 & 0xFF)];
                    sBox[2 * i + 1] = MDS[1, (P[P_11][b1x] & 0xFF) ^ ((k0 >> 8) & 0xFF)];
                    sBox[0x200 + 2 * i] = MDS[2, (P[P_21][b2x] & 0xFF) ^ ((k0 >> 16) & 0xFF)];
                    sBox[0x200 + 2 * i + 1] = MDS[3, (P[P_31][b3x] & 0xFF) ^ ((k0 >> 24) & 0xFF)];
                }
                if ((k64Cnt & 3) == 0)
                {
                    b0x = (uint)((P[P_04][b0x] & 0xFF) ^ (k3 & 0xFF));
                    b1x = (uint)((P[P_14][b1x] & 0xFF) ^ ((k3 >> 8) & 0xFF));
                    b2x = (uint)((P[P_24][b2x] & 0xFF) ^ ((k3 >> 16) & 0xFF));
                    b3x = (uint)((P[P_34][b3x] & 0xFF) ^ ((k3 >> 24) & 0xFF));
                    next = true;
                }
                if ((k64Cnt & 3) == 3 || next)
                {
                    b0x = (uint)((P[P_03][b0x] & 0xFF) ^ (k2 & 0xFF));
                    b1x = (uint)((P[P_13][b1x] & 0xFF) ^ ((k2 >> 8) & 0xFF));
                    b2x = (uint)((P[P_23][b2x] & 0xFF) ^ ((k2 >> 16) & 0xFF));
                    b3x = (uint)((P[P_33][b3x] & 0xFF) ^ ((k2 >> 24) & 0xFF));
                    next = true;
                }
                if ((k64Cnt & 3) == 2 || next)
                {// 128-bit keys
                    sBox[2 * i] = MDS[0, (P[P_01][(P[P_02][b0x] & 0xFF) ^ (k1 & 0xFF)] & 0xFF) ^ (k0 & 0xFF)];
                    sBox[2 * i + 1] = MDS[1, (P[P_11][(P[P_12][b1x] & 0xFF) ^ ((k1 >> 8) & 0xFF)] & 0xFF) ^ ((k0 >> 8) & 0xFF)];
                    sBox[0x200 + 2 * i] = MDS[2, (P[P_21][(P[P_22][b2x] & 0xFF) ^ ((k1 >> 16) & 0xFF)] & 0xFF) ^ ((k0 >> 16) & 0xFF)];
                    sBox[0x200 + 2 * i + 1] = MDS[3, (P[P_31][(P[P_32][b3x] & 0xFF) ^ ((k1 >> 24) & 0xFF)] & 0xFF) ^ ((k0 >> 24) & 0xFF)];

                }
            }

            
        }
        #endregion

        #region Twofish Methods
      

        /**
         * Use (12, 8) Reed-Solomon code over GF(256) to produce a key S-box
         * 32-bit entity from two key material 32-bit entities.
         *
         * @param  k0  1st 32-bit entity.
         * @param  k1  2nd 32-bit entity.
         * @return  Remainder polynomial generated using RS code
         */
        private static uint RS_MDS_Encode(uint k0, uint k1)
        {
            uint r = k1;
            for (uint i = 0; i < 4; i++) // shift 1 byte at a time
                r = RS_rem(r);
            r ^= k0;
            for (uint i = 0; i < 4; i++)
                r = RS_rem(r);
            return r;
        }

        /*
        * Reed-Solomon code parameters: (12, 8) reversible code:<p>
        * <pre>
        *   g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
        * </pre>
        * where a = primitive root of field generator 0x14D
        */
        private static uint RS_rem(uint x)
        {
            uint b = (x >> 24) & 0xFF;
            uint g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
            uint g3 = (b >> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >> 1) : 0) ^ g2;
            uint result = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
            return result;
        }

        private static uint F32(uint k64Cnt, uint x, uint[] k32)
        {
            uint b0x = x & 0xFF;
            uint b1x = ((x >> 8) & 0xFF);
            uint b2x = ((x >> 16) & 0xFF);
            uint b3x = ((x >> 24) & 0xFF);
            uint k0 = k32[0];
            uint k1 = k32[1];
            uint k2 = k32[2];
            uint k3 = k32[3];

            uint result = 0;
            switch (k64Cnt & 3)
            {
                case 1:
                    result =
                       MDS[0, (P[P_01][b0x] & 0xFF) ^ (k0 & 0xFF)] ^
                       MDS[1, (P[P_11][b1x] & 0xFF) ^ ((k0 >> 8) & 0xFF)] ^
                       MDS[2, (P[P_21][b2x] & 0xFF) ^ ((k0 >> 16) & 0xFF)] ^
                       MDS[3, (P[P_31][b3x] & 0xFF) ^ ((k0 >> 24) & 0xFF)];
                    break;
                case 0:  // same as 4
                    b0x = (uint)((P[P_04][b0x] & 0xFF) ^ (k3 & 0xFF));
                    b1x = (uint)((P[P_14][b1x] & 0xFF) ^ ((k3 >> 8) & 0xFF));
                    b2x = (uint)((P[P_24][b2x] & 0xFF) ^ ((k3 >> 16) & 0xFF));
                    b3x = (uint)((P[P_34][b3x] & 0xFF) ^ ((k3 >> 24) & 0xFF));
                    goto case 3;
                case 3:
                    b0x = (uint)((P[P_03][b0x] & 0xFF) ^ (k2 & 0xFF));
                    b1x = (uint)((P[P_13][b1x] & 0xFF) ^ ((k2 >> 8) & 0xFF));
                    b2x = (uint)((P[P_23][b2x] & 0xFF) ^ ((k2 >> 16) & 0xFF));
                    b3x = (uint)((P[P_33][b3x] & 0xFF) ^ ((k2 >> 24) & 0xFF));
                    goto case 2;
                case 2:                             // 128-bit keys (optimize for this case)
                    result =
                       MDS[0, (P[P_01][(P[P_02][b0x] & 0xFF) ^ (k1 & 0xFF)] & 0xFF) ^ (k0 & 0xFF)] ^
                       MDS[1, (P[P_11][(P[P_12][b1x] & 0xFF) ^ ((k1 >> 8) & 0xFF)] & 0xFF) ^ ((k0 >> 8) & 0xFF)] ^
                       MDS[2, (P[P_21][(P[P_22][b2x] & 0xFF) ^ ((k1 >> 16) & 0xFF)] & 0xFF) ^ ((k0 >> 16) & 0xFF)] ^
                       MDS[3, (P[P_31][(P[P_32][b3x] & 0xFF) ^ ((k1 >> 24) & 0xFF)] & 0xFF) ^ ((k0 >> 24) & 0xFF)];
                    break;
            }
            return result;
        }


      

        private uint Fe32_b0(uint x)
        {
            return sBox[2 * (x & 0xFF)] ^
                   sBox[2 * ((x >> 8) & 0xFF) + 1] ^
                   sBox[0x200 + 2 * ((x >> 16) & 0xFF)] ^
                   sBox[0x201 + 2 * ((x >> 24) & 0xFF)];
        }

     

        private uint Fe32_b3(uint x)
        {
            return sBox[2 * ((x >> 24) & 0xFF)] ^
                   sBox[2 * (x & 0xFF) + 1] ^
                   sBox[0x200 + 2 * ((x >> 8) & 0xFF)] ^
                   sBox[0x201 + 2 * ((x >> 16) & 0xFF)];
        }
      
        #endregion  

        #region BlockEncrypt
        protected void BlockEncrypt(byte[] input, byte[] output)
        {

            uint x0 = (uint)((input[0] & 0xFF))       |
                      (uint)((input[1] & 0xFF) <<  8) |
                      (uint)((input[2] & 0xFF) << 16) |
                      (uint)((input[3] & 0xFF) << 24);
            uint x1 = (uint)((input[4] & 0xFF))       |
                      (uint)((input[5] & 0xFF) <<  8) |
                      (uint)((input[6] & 0xFF) << 16) |
                      (uint)((input[7] & 0xFF) << 24);
            uint x2 = (uint)((input[8] & 0xFF))       |
                      (uint)((input[9] & 0xFF) <<  8) |
                      (uint)((input[10] & 0xFF) << 16) |
                      (uint)((input[11] & 0xFF) << 24);
            uint x3 = (uint)((input[12] & 0xFF))       |
                      (uint)((input[13] & 0xFF) <<  8) |
                      (uint)((input[14] & 0xFF) << 16) |
                      (uint)((input[15] & 0xFF) << 24);
        

            x0 ^= subKeys[0];
            x1 ^= subKeys[1];
            x2 ^= subKeys[2];
            x3 ^= subKeys[3];

            

            uint t0, t1;
          

            #region Encrypt-Rounds
            //R=0           
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[8];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[9];

            
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[10];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[11];


            //R=2           
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[12];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[13];

            
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[14];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[15];


            //R=4            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[16];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[17];

           
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[18];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[19];


            //R=6            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[20];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[21];

            
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[22];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[23];


            //R=8           
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[24];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[25];

           
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[26];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[27];


            //R=10            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[28];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[29];

          
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[30];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[31];


            //R=12            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[32];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[33];

           
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];            
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[34];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[35];


            //R=14            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];           
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x2 ^= t0 + t1 + subKeys[36];
            x2 = x2 >> 1 | x2 << 31;
            x3 = x3 << 1 | x3 >> 31;
            x3 ^= t0 + (t1 << 1) + subKeys[37];

           
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x0 ^= t0 + t1 + subKeys[38];
            x0 = x0 >> 1 | x0 << 31;
            x1 = x1 << 1 | x1 >> 31;
            x1 ^= t0 + (t1 << 1) + subKeys[39]; 
            #endregion

            

            x2 ^= subKeys[4];
            x3 ^= subKeys[5];
            x0 ^= subKeys[6];
            x1 ^= subKeys[7];

            output[0] = (byte)(x2 & 0xFF);
            output[1] = (byte)((x2>> 8) & 0xFF);
            output[2] = (byte)((x2>> 16) & 0xFF);
            output[3] = (byte)((x2>> 24) & 0xFF);

            output[4] = (byte)(x3 & 0xFF);
            output[5] = (byte)((x3>> 8) & 0xFF);
            output[6] = (byte)((x3>> 16) & 0xFF);
            output[7] = (byte)((x3>> 24) & 0xFF);

            output[8] = (byte)(x0 & 0xFF);
            output[9] = (byte)((x0>> 8) & 0xFF);
            output[10] = (byte)((x0>> 16) & 0xFF);
            output[11] = (byte)((x0>> 24) & 0xFF);

            output[12] = (byte)(x1 & 0xFF);
            output[13] = (byte)((x1>> 8) & 0xFF);
            output[14] = (byte)((x1>> 16) & 0xFF);
            output[15] = (byte)((x1>> 24) & 0xFF);
        }

        #endregion

        #region BlockDecrypt

        protected void BlockDecrypt(byte[] input, byte[] output)
        {
            uint x2 = (uint)((input[0] & 0xFF)) |
                      (uint)((input[1] & 0xFF) << 8) |
                      (uint)((input[2] & 0xFF) << 16) |
                      (uint)((input[3] & 0xFF) << 24);
            uint x3 = (uint)((input[4] & 0xFF)) |
                      (uint)((input[5] & 0xFF) << 8) |
                      (uint)((input[6] & 0xFF) << 16) |
                      (uint)((input[7] & 0xFF) << 24);
            uint x0 = (uint)((input[8] & 0xFF)) |
                      (uint)((input[9] & 0xFF) << 8) |
                      (uint)((input[10] & 0xFF) << 16) |
                      (uint)((input[11] & 0xFF) << 24);
            uint x1 = (uint)((input[12] & 0xFF)) |
                      (uint)((input[13] & 0xFF) << 8) |
                      (uint)((input[14] & 0xFF) << 16) |
                      (uint)((input[15] & 0xFF) << 24);

            x2 ^= subKeys[4];
            x3 ^= subKeys[5];
            x0 ^= subKeys[6];
            x1 ^= subKeys[7];
             
            
            
            uint t0, t1;

            #region Decrypt-Rounds
            //R=0            
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[39];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[38];

            
            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[37];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[36];

            //R=2
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[35];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[34];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[33];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[32];

            //R=4
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[31];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[30];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[29];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[28];

            //R=6
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[27];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[26];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[25];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[24];

            //R=8
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[23];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[22];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[21];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[20];

            //R=10
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[19];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[18];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[17];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[16];

            //R=12
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[15];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[14];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[13];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[12];

            //R=14
            t0 = sBox[(x2 & 0xFF) << 1] ^ sBox[(((x2 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x2 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x2 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x3 >> 24) & 0xFF) << 1] ^ sBox[((x3 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x3 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x3 >> 16) & 0xFF) << 1)];

            x1 ^= t0 + (t1 << 1) + subKeys[11];
            x1 = x1 >> 1 | x1 << 31;
            x0 = x0 << 1 | x0 >> 31;
            x0 ^= t0 + t1 + subKeys[10];


            t0 = sBox[(x0 & 0xFF) << 1] ^ sBox[(((x0 >> 8) & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x0 >> 16) & 0xFF) << 1)] ^ sBox[0x201 | (((x0 >> 24) & 0xFF) << 1)];
            t1 = sBox[((x1 >> 24) & 0xFF) << 1] ^ sBox[((x1 & 0xFF) << 1) | 1] ^ sBox[0x200 | (((x1 >> 8) & 0xFF) << 1)] ^ sBox[0x201 | (((x1 >> 16) & 0xFF) << 1)];

            x3 ^= t0 + (t1 << 1) + subKeys[9];
            x3 = x3 >> 1 | x3 << 31;
            x2 = x2 << 1 | x2 >> 31;
            x2 ^= t0 + t1 + subKeys[8];


            #endregion

     
 
            x0 ^= subKeys[0];
            x1 ^= subKeys[1];
            x2 ^= subKeys[2];
            x3 ^= subKeys[3];

            output[0] = (byte)(x0 & 0xFF);
            output[1] = (byte)((x0 >> 8) & 0xFF);
            output[2] = (byte)((x0 >> 16) & 0xFF);
            output[3] = (byte)((x0 >> 24) & 0xFF);

            output[4] = (byte)(x1 & 0xFF);
            output[5] = (byte)((x1 >> 8) & 0xFF);
            output[6] = (byte)((x1 >> 16) & 0xFF);
            output[7] = (byte)((x1 >> 24) & 0xFF);

            output[8] = (byte)(x2 & 0xFF);
            output[9] = (byte)((x2 >> 8) & 0xFF);
            output[10] = (byte)((x2 >> 16) & 0xFF);
            output[11] = (byte)((x2 >> 24) & 0xFF);

            output[12] = (byte)(x3 & 0xFF);
            output[13] = (byte)((x3 >> 8) & 0xFF);
            output[14] = (byte)((x3 >> 16) & 0xFF);
            output[15] = (byte)((x3 >> 24) & 0xFF);
        }
        #endregion


    }


    #endregion
}
