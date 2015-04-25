// Serpent.cs - An implementation in C# of the Serpent cipher

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
     * 
     * Serpent is a 128-bit 32-round block cipher with variable key lengths,
     * including 128-, 192- and 256-bit keys conjectured to be at least as
     * secure as three-key triple-DES.<p>
     *
     * Serpent was designed by Ross Anderson, Eli Biham and Lars Knudsen as a
     * candidate algorithm for the NIST AES Quest.<p>
     *
     * References:<ol>
     *  Serpent: A New Block Cipher Proposal. This paper was published in the
     *  proceedings of the "Fast Software Encryption Workshop No. 5" held in
     *  Paris in March 1998. LNCS, Springer Verlag.
     *  Reference implementation of the standard Serpent cipher written in C
     *  by Frank Stajano (http://www.cl.cam.ac.uk/~fms/)   
     */

    /// <summary>
    /// Blockcipher Serpent (one of the 5 AES finalists) 
    /// </summary>
    public class Serpent : SymmetricAlgorithm
    {
        CryptRand rng = CryptRand.Instance;

        public Serpent()
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
            return new SerpentTransform(this, false, rgbKey, rgbIV);            
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new SerpentTransform(this, true, rgbKey, rgbIV);           
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


    #region Serpent Transform
    /* Ported from Java to C# by Nils Reimers
     * 
     ** References:     
     * Serpent_Bitslice.java     
     *    Copyright 1997, 1998 by
     *    Systemics Ltd (http://www.systemics.com/) on behalf of the
     *    Cryptix Development Team (http://www.systemics.com/docs/cryptix/)
     */

    internal class  SerpentTransform : SymmetricTransform
    {
        private bool encryption;
        protected uint[] sesKey;
        

        public SerpentTransform(Serpent algo, bool encryption, byte[] key, byte[] iv)
            : base(algo, encryption, iv)
        {
            if ((iv != null) && (iv.Length != (algo.BlockSize >> 3)))
                throw new CryptographicException("IV length is invalid (" + iv.Length + " bytes), it should be " + (algo.BlockSize >> 3) + "bytes long.");

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
                BlockDecypt(input, output);           
        }

        protected override void Dispose(bool disposing)
        {
            //Delete Session Key
            for (int i = 0; i < sesKey.Length; i++)
                sesKey[i] = 0x00;

            sesKey = null;

            base.Dispose(disposing);
        }
                  

        #region Constans
        private const uint BLOCK_SIZE =  16; // bytes in a data-block

        private const int ROUNDS = 32;              // nbr of rounds
        private const uint PHI = 0x9E3779B9; // (sqrt(5) - 1) * 2**31
        #endregion

        #region Sbox
        private static byte[][] Sbox = new byte[][] {
	    new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	    new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	    new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	    new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	    new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	    new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	    new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	    new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	    new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	    new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	    new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	    new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	    new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	    new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	    new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	    new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	    new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	    new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	    new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	    new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	    new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	    new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	    new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	    new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	    new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	    new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	    new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	    new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	    new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	    new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	    new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	    new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } /* S7: */
        };

        private static byte[][] SboxInverse = new byte[][] {
	    new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	    new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	    new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	    new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	    new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	    new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	    new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	    new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	    new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	    new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	    new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	    new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	    new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	    new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	    new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	    new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	    new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	    new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	    new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	    new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	    new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	    new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	    new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	    new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	    new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	    new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	    new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	    new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	    new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	    new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	    new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	    new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } /* InvS7: */
        };

        #endregion

        #region MakeKey
        protected void MakeKey(byte[] key)
        {
            sesKey = new uint[4 * (ROUNDS + 1)];
            uint limit = (uint)(key.Length/4);
            uint i, t, offset = (uint)key.Length-1;
            int j;

            for (i = 0; i < limit; i++)
                sesKey[i] = (uint)(key[offset--] & 0xFF) |
                       (uint)((key[offset--] & 0xFF)) <<  8 |
                       (uint)((key[offset--] & 0xFF)) << 16 |
                       (uint)((key[offset--] & 0xFF)) << 24;

            if (i < 8)
                sesKey[i++] = 1;
                    //for (; i < 8; i++)
                    //   w[i] = 0;

            // (b) and expanding them to full 132 x 32-bit material
            // this is a literal implementation of the Serpent paper
            // (section 4 The Key Schedule, p.226)
            //
            // start by computing the first 8 values using the second
            // lot of 8 values as an intermediary buffer
            for (i = 8, j = 0; i < 16; i++) {
                t = (uint)(sesKey[j] ^ sesKey[i-5] ^ sesKey[i-3] ^ sesKey[i-1] ^ PHI ^ j++);
                sesKey[i] = t << 11 | t >> 21;
            }
            // translate the buffer by -8
            for (i = 0; i < 8; i++) 
                sesKey[i] = sesKey[i+8];


            limit = 132; // 132 for a 32-round Serpent
            // finish computing the remaining intermediary subkeys
            for ( ; i < limit; i++) {
                t = (uint)(sesKey[i-8] ^ sesKey[i-5] ^ sesKey[i-3] ^ sesKey[i-1] ^ PHI ^ i);
                sesKey[i] = t << 11 | t >> 21;
            }


            // compute intermediary key. use the same array as prekeys
            uint x0, x1, x2, x3, y0, y1, y2, y3, z;
            byte[] sb;
            for (i = 0; i < ROUNDS + 1; i++) {
                x0 = sesKey[4*i    ];
                x1 = sesKey[4*i + 1];
                x2 = sesKey[4*i + 2];
                x3 = sesKey[4*i + 3];
                y0 = y1 = y2 = y3 = 0;
                sb = Sbox[(ROUNDS + 3 - i) % ROUNDS];
                for (j = 0; j < 32; j++) {
                    z = sb[((x0 >> j) & 0x01)      |
                           ((x1 >> j) & 0x01) << 1 |
                           ((x2 >> j) & 0x01) << 2 |
                           ((x3 >> j) & 0x01) << 3];
                    y0 |= ( z        & 0x01) << j;
                    y1 |= ((z >> 1) & 0x01) << j;
                    y2 |= ((z >> 2) & 0x01) << j;
                    y3 |= ((z >> 3) & 0x01) << j;
                }
                sesKey[4*i    ] = y0;
                sesKey[4*i + 1] = y1;
                sesKey[4*i + 2] = y2;
                sesKey[4*i + 3] = y3;
            }
           
           

        }
        #endregion

        #region BlockEncrypt
        protected void BlockEncrypt(byte[] input, byte[] output)
        {
            uint x0 = (uint)((input[15] & 0xFF)) |
                      (uint)((input[14] & 0xFF)) <<  8 |
                      (uint)((input[13] & 0xFF)) << 16 |
                      (uint)((input[12] & 0xFF)) << 24;

            uint x1 = (uint)((input[11] & 0xFF))       |
                      (uint)((input[10] & 0xFF)) <<  8 |
                      (uint)((input[9] & 0xFF)) << 16 |
                      (uint)((input[8] & 0xFF)) << 24;

            uint x2 = (uint)((input[7] & 0xFF))       |
                      (uint)((input[6] & 0xFF)) <<  8 |
                      (uint)((input[5] & 0xFF)) << 16 |
                      (uint)((input[4] & 0xFF)) << 24;

            uint x3 = (uint)((input[3] & 0xFF))       |
                      (uint)((input[2] & 0xFF)) <<  8 |
                      (uint)((input[1] & 0xFF)) << 16 |
                      (uint)((input[0] & 0xFF)) << 24;

          


           

            uint y0, y1, y2, y3;
            uint t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15, t16, t17, t18;
  
            x0 ^=  sesKey[0];
            x1 ^=  sesKey[1];
            x2 ^=  sesKey[2];
            x3 ^=  sesKey[3] ;

            /* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

            /* depth = 5,7,4,2, Total gates=18 */

            t01 = x1  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  ^ x1 ;
            y3  = t02 ^ t01;
            t05 = x2  | y3 ;
            t06 = x0  ^ x3 ;
            t07 = x1  | x2 ;
            t08 = x3  & t05;
            t09 = t03 & t07;
            y2  = t09 ^ t08;
            t11 = t09 & y2 ;
            t12 = x2  ^ x3 ;
            t13 = t07 ^ t11;
            t14 = x1  & t06;
            t15 = t06 ^ t13;
            y0  =     ~ t15;
            t17 = y0  ^ t14;
            y1  = t12 ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 1*4+0];
            x1 ^=  sesKey[ 1*4+1];
            x2 ^=  sesKey[ 1*4+2];
            x3 ^=  sesKey[ 1*4+3] ;

            /* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

            /* depth = 10,7,3,5, Total gates=18 */

            t01 = x0  | x3 ;
            t02 = x2  ^ x3 ;
            t03 =     ~ x1 ;
            t04 = x0  ^ x2 ;
            t05 = x0  | t03;
            t06 = x3  & t04;
            t07 = t01 & t02;
            t08 = x1  | t06;
            y2  = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2  ^ t11;
            t13 = x1  & x3 ;
            y3  =     ~ t10;
            y1  = t13 ^ t12;
            t16 = t10 | y1 ;
            t17 = t05 & t16;
            y0  = x2  ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 2*4+0];
            x1 ^=  sesKey[ 2*4+1];
            x2 ^=  sesKey[ 2*4+2];
            x3 ^=  sesKey[ 2*4+3] ;

            /* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

            /* depth = 3,8,11,7, Total gates=16 */

            t01 = x0  | x2 ;
            t02 = x0  ^ x1 ;
            t03 = x3  ^ t01;
            y0  = t02 ^ t03;
            t05 = x2  ^ y0 ;
            t06 = x1  ^ t05;
            t07 = x1  | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1  = t10 ^ t08;
            t12 = x0  | x3 ;
            t13 = t09 ^ y1 ;
            t14 = x1  ^ t13;
            y3  =     ~ t09;
            y2  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 3*4+0];
            x1 ^=  sesKey[ 3*4+1];
            x2 ^=  sesKey[ 3*4+2];
            x3 ^=  sesKey[ 3*4+3] ;

            /* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

            /* depth = 8,3,5,5, Total gates=18 */

            t01 = x0  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  & x3 ;
            t04 = t01 & t02;
            t05 = x1  | t03;
            t06 = x0  & x1 ;
            t07 = x3  ^ t04;
            t08 = x2  | t06;
            t09 = x1  ^ t07;
            t10 = x3  & t05;
            t11 = t02 ^ t10;
            y3  = t08 ^ t09;
            t13 = x3  | y3 ;
            t14 = x0  | t07;
            t15 = x1  & t13;
            y2  = t08 ^ t11;
            y0  = t14 ^ t15;
            y1  = t05 ^ t04;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 4*4+0];
            x1 ^=  sesKey[ 4*4+1];
            x2 ^=  sesKey[ 4*4+2];
            x3 ^=  sesKey[ 4*4+3] ;

            /* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

            /* depth = 6,7,5,3, Total gates=19 */

            t01 = x0  | x1 ;
            t02 = x1  | x2 ;
            t03 = x0  ^ t02;
            t04 = x1  ^ x3 ;
            t05 = x3  | t03;
            t06 = x3  & t01;
            y3  = t03 ^ t06;
            t08 = y3  & t04;
            t09 = t04 & t05;
            t10 = x2  ^ t06;
            t11 = x1  & x2 ;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0  & t05;
            t16 = t11 | t12;
            y2  = t13 ^ t08;
            y1  = t15 ^ t16;
            y0  =     ~ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 5*4+0];
            x1 ^=  sesKey[ 5*4+1];
            x2 ^=  sesKey[ 5*4+2];
            x3 ^=  sesKey[ 5*4+3] ;

            /* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

            /* depth = 4,6,8,6, Total gates=17 */

            t01 = x1  ^ x3 ;
            t02 = x1  | x3 ;
            t03 = x0  & t01;
            t04 = x2  ^ t02;
            t05 = t03 ^ t04;
            y0  =     ~ t05;
            t07 = x0  ^ t01;
            t08 = x3  | y0 ;
            t09 = x1  | t05;
            t10 = x3  ^ t08;
            t11 = x1  | t07;
            t12 = t03 | y0 ;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2  = t09 ^ t13;
            y1  = t07 ^ t08;
            y3  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 6*4+0];
            x1 ^=  sesKey[ 6*4+1];
            x2 ^=  sesKey[ 6*4+2];
            x3 ^=  sesKey[ 6*4+3] ;

            /* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

            /* depth = 8,3,6,3, Total gates=19 */

            t01 = x0  & x3 ;
            t02 = x1  ^ x2 ;
            t03 = x0  ^ x3 ;
            t04 = t01 ^ t02;
            t05 = x1  | x2 ;
            y1  =     ~ t04;
            t07 = t03 & t05;
            t08 = x1  & y1 ;
            t09 = x0  | x2 ;
            t10 = t07 ^ t08;
            t11 = x1  | x3 ;
            t12 = x2  ^ t11;
            t13 = t09 ^ t10;
            y2  =     ~ t13;
            t15 = y1  & t03;
            y3  = t12 ^ t07;
            t17 = x0  ^ x1 ;
            t18 = y2  ^ t15;
            y0  = t17 ^ t18;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 7*4+0];
            x1 ^=  sesKey[ 7*4+1];
            x2 ^=  sesKey[ 7*4+2];
            x3 ^=  sesKey[ 7*4+3] ;

            /* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

            /* depth = 10,7,10,4, Total gates=19 */

            t01 = x0  & x2 ;
            t02 =     ~ x3 ;
            t03 = x0  & t02;
            t04 = x1  | t01;
            t05 = x0  & x1 ;
            t06 = x2  ^ t04;
            y3  = t03 ^ t06;
            t08 = x2  | y3 ;
            t09 = x3  | t05;
            t10 = x0  ^ t08;
            t11 = t04 & y3 ;
            y1  = t09 ^ t10;
            t13 = x1  ^ y1 ;
            t14 = t01 ^ y1 ;
            t15 = x2  ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0  = t15 ^ t17;
            y2  = x0  ^ t16;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 8*4+0];
            x1 ^=  sesKey[ 8*4+1];
            x2 ^=  sesKey[ 8*4+2];
            x3 ^=  sesKey[ 8*4+3] ;

            /* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

            /* depth = 5,7,4,2, Total gates=18 */

            t01 = x1  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  ^ x1 ;
            y3  = t02 ^ t01;
            t05 = x2  | y3 ;
            t06 = x0  ^ x3 ;
            t07 = x1  | x2 ;
            t08 = x3  & t05;
            t09 = t03 & t07;
            y2  = t09 ^ t08;
            t11 = t09 & y2 ;
            t12 = x2  ^ x3 ;
            t13 = t07 ^ t11;
            t14 = x1  & t06;
            t15 = t06 ^ t13;
            y0  =     ~ t15;
            t17 = y0  ^ t14;
            y1  = t12 ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[ 9*4+0];
            x1 ^=  sesKey[ 9*4+1];
            x2 ^=  sesKey[ 9*4+2];
            x3 ^=  sesKey[ 9*4+3] ;

            /* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

            /* depth = 10,7,3,5, Total gates=18 */

            t01 = x0  | x3 ;
            t02 = x2  ^ x3 ;
            t03 =     ~ x1 ;
            t04 = x0  ^ x2 ;
            t05 = x0  | t03;
            t06 = x3  & t04;
            t07 = t01 & t02;
            t08 = x1  | t06;
            y2  = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2  ^ t11;
            t13 = x1  & x3 ;
            y3  =     ~ t10;
            y1  = t13 ^ t12;
            t16 = t10 | y1 ;
            t17 = t05 & t16;
            y0  = x2  ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[10*4+0];
            x1 ^=  sesKey[10*4+1];
            x2 ^=  sesKey[10*4+2];
            x3 ^=  sesKey[10*4+3] ;

            /* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

            /* depth = 3,8,11,7, Total gates=16 */

            t01 = x0  | x2 ;
            t02 = x0  ^ x1 ;
            t03 = x3  ^ t01;
            y0  = t02 ^ t03;
            t05 = x2  ^ y0 ;
            t06 = x1  ^ t05;
            t07 = x1  | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1  = t10 ^ t08;
            t12 = x0  | x3 ;
            t13 = t09 ^ y1 ;
            t14 = x1  ^ t13;
            y3  =     ~ t09;
            y2  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[11*4+0];
            x1 ^=  sesKey[11*4+1];
            x2 ^=  sesKey[11*4+2];
            x3 ^=  sesKey[11*4+3] ;

            /* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

            /* depth = 8,3,5,5, Total gates=18 */

            t01 = x0  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  & x3 ;
            t04 = t01 & t02;
            t05 = x1  | t03;
            t06 = x0  & x1 ;
            t07 = x3  ^ t04;
            t08 = x2  | t06;
            t09 = x1  ^ t07;
            t10 = x3  & t05;
            t11 = t02 ^ t10;
            y3  = t08 ^ t09;
            t13 = x3  | y3 ;
            t14 = x0  | t07;
            t15 = x1  & t13;
            y2  = t08 ^ t11;
            y0  = t14 ^ t15;
            y1  = t05 ^ t04;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[12*4+0];
            x1 ^=  sesKey[12*4+1];
            x2 ^=  sesKey[12*4+2];
            x3 ^=  sesKey[12*4+3] ;

            /* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

            /* depth = 6,7,5,3, Total gates=19 */

            t01 = x0  | x1 ;
            t02 = x1  | x2 ;
            t03 = x0  ^ t02;
            t04 = x1  ^ x3 ;
            t05 = x3  | t03;
            t06 = x3  & t01;
            y3  = t03 ^ t06;
            t08 = y3  & t04;
            t09 = t04 & t05;
            t10 = x2  ^ t06;
            t11 = x1  & x2 ;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0  & t05;
            t16 = t11 | t12;
            y2  = t13 ^ t08;
            y1  = t15 ^ t16;
            y0  =     ~ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[13*4+0];
            x1 ^=  sesKey[13*4+1];
            x2 ^=  sesKey[13*4+2];
            x3 ^=  sesKey[13*4+3] ;

            /* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

            /* depth = 4,6,8,6, Total gates=17 */

            t01 = x1  ^ x3 ;
            t02 = x1  | x3 ;
            t03 = x0  & t01;
            t04 = x2  ^ t02;
            t05 = t03 ^ t04;
            y0  =     ~ t05;
            t07 = x0  ^ t01;
            t08 = x3  | y0 ;
            t09 = x1  | t05;
            t10 = x3  ^ t08;
            t11 = x1  | t07;
            t12 = t03 | y0 ;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2  = t09 ^ t13;
            y1  = t07 ^ t08;
            y3  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[14*4+0];
            x1 ^=  sesKey[14*4+1];
            x2 ^=  sesKey[14*4+2];
            x3 ^=  sesKey[14*4+3] ;

            /* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

            /* depth = 8,3,6,3, Total gates=19 */

            t01 = x0  & x3 ;
            t02 = x1  ^ x2 ;
            t03 = x0  ^ x3 ;
            t04 = t01 ^ t02;
            t05 = x1  | x2 ;
            y1  =     ~ t04;
            t07 = t03 & t05;
            t08 = x1  & y1 ;
            t09 = x0  | x2 ;
            t10 = t07 ^ t08;
            t11 = x1  | x3 ;
            t12 = x2  ^ t11;
            t13 = t09 ^ t10;
            y2  =     ~ t13;
            t15 = y1  & t03;
            y3  = t12 ^ t07;
            t17 = x0  ^ x1 ;
            t18 = y2  ^ t15;
            y0  = t17 ^ t18;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[15*4+0];
            x1 ^=  sesKey[15*4+1];
            x2 ^=  sesKey[15*4+2];
            x3 ^=  sesKey[15*4+3] ;

            /* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

            /* depth = 10,7,10,4, Total gates=19 */

            t01 = x0  & x2 ;
            t02 =     ~ x3 ;
            t03 = x0  & t02;
            t04 = x1  | t01;
            t05 = x0  & x1 ;
            t06 = x2  ^ t04;
            y3  = t03 ^ t06;
            t08 = x2  | y3 ;
            t09 = x3  | t05;
            t10 = x0  ^ t08;
            t11 = t04 & y3 ;
            y1  = t09 ^ t10;
            t13 = x1  ^ y1 ;
            t14 = t01 ^ y1 ;
            t15 = x2  ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0  = t15 ^ t17;
            y2  = x0  ^ t16;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[16*4+0];
            x1 ^=  sesKey[16*4+1];
            x2 ^=  sesKey[16*4+2];
            x3 ^=  sesKey[16*4+3] ;

            /* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

            /* depth = 5,7,4,2, Total gates=18 */

            t01 = x1  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  ^ x1 ;
            y3  = t02 ^ t01;
            t05 = x2  | y3 ;
            t06 = x0  ^ x3 ;
            t07 = x1  | x2 ;
            t08 = x3  & t05;
            t09 = t03 & t07;
            y2  = t09 ^ t08;
            t11 = t09 & y2 ;
            t12 = x2  ^ x3 ;
            t13 = t07 ^ t11;
            t14 = x1  & t06;
            t15 = t06 ^ t13;
            y0  =     ~ t15;
            t17 = y0  ^ t14;
            y1  = t12 ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[17*4+0];
            x1 ^=  sesKey[17*4+1];
            x2 ^=  sesKey[17*4+2];
            x3 ^=  sesKey[17*4+3] ;

            /* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

            /* depth = 10,7,3,5, Total gates=18 */

            t01 = x0  | x3 ;
            t02 = x2  ^ x3 ;
            t03 =     ~ x1 ;
            t04 = x0  ^ x2 ;
            t05 = x0  | t03;
            t06 = x3  & t04;
            t07 = t01 & t02;
            t08 = x1  | t06;
            y2  = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2  ^ t11;
            t13 = x1  & x3 ;
            y3  =     ~ t10;
            y1  = t13 ^ t12;
            t16 = t10 | y1 ;
            t17 = t05 & t16;
            y0  = x2  ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[18*4+0];
            x1 ^=  sesKey[18*4+1];
            x2 ^=  sesKey[18*4+2];
            x3 ^=  sesKey[18*4+3] ;

            /* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

            /* depth = 3,8,11,7, Total gates=16 */

            t01 = x0  | x2 ;
            t02 = x0  ^ x1 ;
            t03 = x3  ^ t01;
            y0  = t02 ^ t03;
            t05 = x2  ^ y0 ;
            t06 = x1  ^ t05;
            t07 = x1  | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1  = t10 ^ t08;
            t12 = x0  | x3 ;
            t13 = t09 ^ y1 ;
            t14 = x1  ^ t13;
            y3  =     ~ t09;
            y2  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[19*4+0];
            x1 ^=  sesKey[19*4+1];
            x2 ^=  sesKey[19*4+2];
            x3 ^=  sesKey[19*4+3] ;

            /* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

            /* depth = 8,3,5,5, Total gates=18 */

            t01 = x0  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  & x3 ;
            t04 = t01 & t02;
            t05 = x1  | t03;
            t06 = x0  & x1 ;
            t07 = x3  ^ t04;
            t08 = x2  | t06;
            t09 = x1  ^ t07;
            t10 = x3  & t05;
            t11 = t02 ^ t10;
            y3  = t08 ^ t09;
            t13 = x3  | y3 ;
            t14 = x0  | t07;
            t15 = x1  & t13;
            y2  = t08 ^ t11;
            y0  = t14 ^ t15;
            y1  = t05 ^ t04;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[20*4+0];
            x1 ^=  sesKey[20*4+1];
            x2 ^=  sesKey[20*4+2];
            x3 ^=  sesKey[20*4+3] ;

            /* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

            /* depth = 6,7,5,3, Total gates=19 */

            t01 = x0  | x1 ;
            t02 = x1  | x2 ;
            t03 = x0  ^ t02;
            t04 = x1  ^ x3 ;
            t05 = x3  | t03;
            t06 = x3  & t01;
            y3  = t03 ^ t06;
            t08 = y3  & t04;
            t09 = t04 & t05;
            t10 = x2  ^ t06;
            t11 = x1  & x2 ;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0  & t05;
            t16 = t11 | t12;
            y2  = t13 ^ t08;
            y1  = t15 ^ t16;
            y0  =     ~ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[21*4+0];
            x1 ^=  sesKey[21*4+1];
            x2 ^=  sesKey[21*4+2];
            x3 ^=  sesKey[21*4+3] ;

            /* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

            /* depth = 4,6,8,6, Total gates=17 */

            t01 = x1  ^ x3 ;
            t02 = x1  | x3 ;
            t03 = x0  & t01;
            t04 = x2  ^ t02;
            t05 = t03 ^ t04;
            y0  =     ~ t05;
            t07 = x0  ^ t01;
            t08 = x3  | y0 ;
            t09 = x1  | t05;
            t10 = x3  ^ t08;
            t11 = x1  | t07;
            t12 = t03 | y0 ;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2  = t09 ^ t13;
            y1  = t07 ^ t08;
            y3  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[22*4+0];
            x1 ^=  sesKey[22*4+1];
            x2 ^=  sesKey[22*4+2];
            x3 ^=  sesKey[22*4+3] ;

            /* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

            /* depth = 8,3,6,3, Total gates=19 */

            t01 = x0  & x3 ;
            t02 = x1  ^ x2 ;
            t03 = x0  ^ x3 ;
            t04 = t01 ^ t02;
            t05 = x1  | x2 ;
            y1  =     ~ t04;
            t07 = t03 & t05;
            t08 = x1  & y1 ;
            t09 = x0  | x2 ;
            t10 = t07 ^ t08;
            t11 = x1  | x3 ;
            t12 = x2  ^ t11;
            t13 = t09 ^ t10;
            y2  =     ~ t13;
            t15 = y1  & t03;
            y3  = t12 ^ t07;
            t17 = x0  ^ x1 ;
            t18 = y2  ^ t15;
            y0  = t17 ^ t18;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[23*4+0];
            x1 ^=  sesKey[23*4+1];
            x2 ^=  sesKey[23*4+2];
            x3 ^=  sesKey[23*4+3] ;

            /* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

            /* depth = 10,7,10,4, Total gates=19 */

            t01 = x0  & x2 ;
            t02 =     ~ x3 ;
            t03 = x0  & t02;
            t04 = x1  | t01;
            t05 = x0  & x1 ;
            t06 = x2  ^ t04;
            y3  = t03 ^ t06;
            t08 = x2  | y3 ;
            t09 = x3  | t05;
            t10 = x0  ^ t08;
            t11 = t04 & y3 ;
            y1  = t09 ^ t10;
            t13 = x1  ^ y1 ;
            t14 = t01 ^ y1 ;
            t15 = x2  ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0  = t15 ^ t17;
            y2  = x0  ^ t16;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[24*4+0];
            x1 ^=  sesKey[24*4+1];
            x2 ^=  sesKey[24*4+2];
            x3 ^=  sesKey[24*4+3] ;

            /* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

            /* depth = 5,7,4,2, Total gates=18 */

            t01 = x1  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  ^ x1 ;
            y3  = t02 ^ t01;
            t05 = x2  | y3 ;
            t06 = x0  ^ x3 ;
            t07 = x1  | x2 ;
            t08 = x3  & t05;
            t09 = t03 & t07;
            y2  = t09 ^ t08;
            t11 = t09 & y2 ;
            t12 = x2  ^ x3 ;
            t13 = t07 ^ t11;
            t14 = x1  & t06;
            t15 = t06 ^ t13;
            y0  =     ~ t15;
            t17 = y0  ^ t14;
            y1  = t12 ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[25*4+0];
            x1 ^=  sesKey[25*4+1];
            x2 ^=  sesKey[25*4+2];
            x3 ^=  sesKey[25*4+3] ;

            /* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

            /* depth = 10,7,3,5, Total gates=18 */

            t01 = x0  | x3 ;
            t02 = x2  ^ x3 ;
            t03 =     ~ x1 ;
            t04 = x0  ^ x2 ;
            t05 = x0  | t03;
            t06 = x3  & t04;
            t07 = t01 & t02;
            t08 = x1  | t06;
            y2  = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2  ^ t11;
            t13 = x1  & x3 ;
            y3  =     ~ t10;
            y1  = t13 ^ t12;
            t16 = t10 | y1 ;
            t17 = t05 & t16;
            y0  = x2  ^ t17;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[26*4+0];
            x1 ^=  sesKey[26*4+1];
            x2 ^=  sesKey[26*4+2];
            x3 ^=  sesKey[26*4+3] ;

            /* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

            /* depth = 3,8,11,7, Total gates=16 */

            t01 = x0  | x2 ;
            t02 = x0  ^ x1 ;
            t03 = x3  ^ t01;
            y0  = t02 ^ t03;
            t05 = x2  ^ y0 ;
            t06 = x1  ^ t05;
            t07 = x1  | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1  = t10 ^ t08;
            t12 = x0  | x3 ;
            t13 = t09 ^ y1 ;
            t14 = x1  ^ t13;
            y3  =     ~ t09;
            y2  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[27*4+0];
            x1 ^=  sesKey[27*4+1];
            x2 ^=  sesKey[27*4+2];
            x3 ^=  sesKey[27*4+3] ;

            /* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

            /* depth = 8,3,5,5, Total gates=18 */

            t01 = x0  ^ x2 ;
            t02 = x0  | x3 ;
            t03 = x0  & x3 ;
            t04 = t01 & t02;
            t05 = x1  | t03;
            t06 = x0  & x1 ;
            t07 = x3  ^ t04;
            t08 = x2  | t06;
            t09 = x1  ^ t07;
            t10 = x3  & t05;
            t11 = t02 ^ t10;
            y3  = t08 ^ t09;
            t13 = x3  | y3 ;
            t14 = x0  | t07;
            t15 = x1  & t13;
            y2  = t08 ^ t11;
            y0  = t14 ^ t15;
            y1  = t05 ^ t04;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[28*4+0];
            x1 ^=  sesKey[28*4+1];
            x2 ^=  sesKey[28*4+2];
            x3 ^=  sesKey[28*4+3] ;

            /* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

            /* depth = 6,7,5,3, Total gates=19 */

            t01 = x0  | x1 ;
            t02 = x1  | x2 ;
            t03 = x0  ^ t02;
            t04 = x1  ^ x3 ;
            t05 = x3  | t03;
            t06 = x3  & t01;
            y3  = t03 ^ t06;
            t08 = y3  & t04;
            t09 = t04 & t05;
            t10 = x2  ^ t06;
            t11 = x1  & x2 ;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0  & t05;
            t16 = t11 | t12;
            y2  = t13 ^ t08;
            y1  = t15 ^ t16;
            y0  =     ~ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[29*4+0];
            x1 ^=  sesKey[29*4+1];
            x2 ^=  sesKey[29*4+2];
            x3 ^=  sesKey[29*4+3] ;

            /* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

            /* depth = 4,6,8,6, Total gates=17 */

            t01 = x1  ^ x3 ;
            t02 = x1  | x3 ;
            t03 = x0  & t01;
            t04 = x2  ^ t02;
            t05 = t03 ^ t04;
            y0  =     ~ t05;
            t07 = x0  ^ t01;
            t08 = x3  | y0 ;
            t09 = x1  | t05;
            t10 = x3  ^ t08;
            t11 = x1  | t07;
            t12 = t03 | y0 ;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2  = t09 ^ t13;
            y1  = t07 ^ t08;
            y3  = t12 ^ t14;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[30*4+0];
            x1 ^=  sesKey[30*4+1];
            x2 ^=  sesKey[30*4+2];
            x3 ^=  sesKey[30*4+3] ;

            /* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

            /* depth = 8,3,6,3, Total gates=19 */

            t01 = x0  & x3 ;
            t02 = x1  ^ x2 ;
            t03 = x0  ^ x3 ;
            t04 = t01 ^ t02;
            t05 = x1  | x2 ;
            y1  =     ~ t04;
            t07 = t03 & t05;
            t08 = x1  & y1 ;
            t09 = x0  | x2 ;
            t10 = t07 ^ t08;
            t11 = x1  | x3 ;
            t12 = x2  ^ t11;
            t13 = t09 ^ t10;
            y2  =     ~ t13;
            t15 = y1  & t03;
            y3  = t12 ^ t07;
            t17 = x0  ^ x1 ;
            t18 = y2  ^ t15;
            y0  = t17 ^ t18;

            x0  = ((((y0))<<(13))| (((y0))>>(32-(13)))) ;
            x2  = ((((y2))<<(3))| (((y2))>>(32-(3)))) ;
            x1  =   y1  ^   x0  ^   x2 ;
            x3  =   y3  ^   x2  ^ (x0)<<3;
            x1  = ((((x1))<<(1))| (((x1))>>(32-(1)))) ;
            x3  = ((((x3))<<(7))| (((x3))>>(32-(7)))) ;
            x0  =   x0  ^   x1  ^   x3 ;
            x2  =   x2  ^   x3  ^ (x1 <<7);
            x0  = ((((x0))<<(5))| (((x0))>>(32-(5)))) ;
            x2  = ((((x2))<<(22))| (((x2))>>(32-(22))))  ;
            x0 ^=  sesKey[31*4+0];
            x1 ^=  sesKey[31*4+1];
            x2 ^=  sesKey[31*4+2];
            x3 ^=  sesKey[31*4+3] ;

            /* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

            /* depth = 10,7,10,4, Total gates=19 */

            t01 = x0  & x2 ;
            t02 =     ~ x3 ;
            t03 = x0  & t02;
            t04 = x1  | t01;
            t05 = x0  & x1 ;
            t06 = x2  ^ t04;
            y3  = t03 ^ t06;
            t08 = x2  | y3 ;
            t09 = x3  | t05;
            t10 = x0  ^ t08;
            t11 = t04 & y3 ;
            y1  = t09 ^ t10;
            t13 = x1  ^ y1 ;
            t14 = t01 ^ y1 ;
            t15 = x2  ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0  = t15 ^ t17;
            y2  = x0  ^ t16;

            x0 = y0;
            x1 = y1;
            x2 = y2;
            x3 = y3;
            x0 ^=  sesKey[32*4+0];
            x1 ^=  sesKey[32*4+1];
            x2 ^=  sesKey[32*4+2];
            x3 ^=  sesKey[32*4+3];


            output[15] = (byte)(x0 & 0xFF);
            output[14] = (byte)((x0 >> 8) & 0xFF);
            output[13] = (byte)((x0 >> 16) & 0xFF);
            output[12] = (byte)((x0 >> 24) & 0xFF);

            output[11] = (byte)(x1 & 0xFF);
            output[10] = (byte)((x1 >> 8) & 0xFF);
            output[9] = (byte)((x1 >> 16) & 0xFF);
            output[8] = (byte)((x1 >> 24) & 0xFF);

            output[7] = (byte)(x2 & 0xFF);
            output[6] = (byte)((x2 >> 8) & 0xFF);
            output[5] = (byte)((x2 >> 16) & 0xFF);
            output[4] = (byte)((x2 >> 24) & 0xFF);

            output[3] = (byte)(x3 & 0xFF);
            output[2] = (byte)((x3 >> 8) & 0xFF);
            output[1] = (byte)((x3 >> 16) & 0xFF);
            output[0] = (byte)((x3 >> 24) & 0xFF);  
        }

        #endregion

        #region BlockDecrypt
        protected void BlockDecypt(byte[] input, byte[] output)
        {
            uint[] K = sesKey;
            uint x0 = (uint)((input[15] & 0xFF)) |
                      (uint)((input[14] & 0xFF)) << 8 |
                      (uint)((input[13] & 0xFF)) << 16 |
                      (uint)((input[12] & 0xFF)) << 24;

            uint x1 = (uint)((input[11] & 0xFF)) |
                      (uint)((input[10] & 0xFF)) << 8 |
                      (uint)((input[9] & 0xFF)) << 16 |
                      (uint)((input[8] & 0xFF)) << 24;

            uint x2 = (uint)((input[7] & 0xFF)) |
                      (uint)((input[6] & 0xFF)) << 8 |
                      (uint)((input[5] & 0xFF)) << 16 |
                      (uint)((input[4] & 0xFF)) << 24;

            uint x3 = (uint)((input[3] & 0xFF)) |
                      (uint)((input[2] & 0xFF)) << 8 |
                      (uint)((input[1] & 0xFF)) << 16 |
                      (uint)((input[0] & 0xFF)) << 24;

  

            uint y0, y1, y2, y3;
            uint t01, t02, t03, t04, t05, t06, t07, t08, t09, t10;
            uint t11, t12, t13, t14, t15, t16, t17, t18;


            x0 ^=  K[32*4+0];  x1 ^=  K[32*4+1];   x2 ^=  K[32*4+2];  x3 ^=  K[32*4+3] ;

            /* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

            /* depth = 9,7,3,3, Total gates=18 */

            t01 = x0  & x1 ;
            t02 = x0  | x1 ;
            t03 = x2  | t01;
            t04 = x3  & t02;
            y3  = t03 ^ t04;
            t06 = x1  ^ t04;
            t07 = x3  ^ y3 ;
            t08 =     ~ t07;
            t09 = t06 | t08;
            t10 = x1  ^ x3 ;
            t11 = x0  | x3 ;
            y1  = x0  ^ t09;
            t13 = x2  ^ t06;
            t14 = x2  & t11;
            t15 = x3  | y1 ;
            t16 = t01 | t10;
            y0  = t13 ^ t15;
            y2  = t14 ^ t16;

            y0 ^=  K[31*4+0];  y1 ^=  K[31*4+1];   y2 ^=  K[31*4+2];  y3 ^=  K[31*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

            /* depth = 5,3,8,6, Total gates=19 */

            t01 = x0  ^ x2 ;
            t02 =     ~ x2 ;
            t03 = x1  & t01;
            t04 = x1  | t02;
            t05 = x3  | t03;
            t06 = x1  ^ x3 ;
            t07 = x0  & t04;
            t08 = x0  | t02;
            t09 = t07 ^ t05;
            y1  = t06 ^ t08;
            y0  =     ~ t09;
            t12 = x1  & y0 ;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3  | t02;
            t17 = x0  ^ y1 ;
            y3  = t17 ^ t15;
            y2  = t16 ^ t14;

            y0 ^=  K[30*4+0];  y1 ^=  K[30*4+1];   y2 ^=  K[30*4+2];  y3 ^=  K[30*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

            /* depth = 4,6,9,7, Total gates=17 */

            t01 = x0  & x3 ;
            t02 = x2  ^ t01;
            t03 = x0  ^ x3 ;
            t04 = x1  & t02;
            t05 = x0  & x2 ;
            y0  = t03 ^ t04;
            t07 = x0  & y0 ;
            t08 = t01 ^ y0 ;
            t09 = x1  | t05;
            t10 =     ~ x1 ;
            y1  = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0  | y1 ;
            y3  = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1  ^ x3 ;
            y2  = t16 ^ t15;

            y0 ^=  K[29*4+0];  y1 ^=  K[29*4+1];   y2 ^=  K[29*4+2];  y3 ^=  K[29*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

            /* depth = 6,4,7,3, Total gates=17 */

            t01 = x1  | x3 ;
            t02 = x2  | x3 ;
            t03 = x0  & t01;
            t04 = x1  ^ t02;
            t05 = x2  ^ x3 ;
            t06 =     ~ t03;
            t07 = x0  & t04;
            y1  = t05 ^ t07;
            t09 = y1  | t06;
            t10 = x0  ^ t07;
            t11 = t01 ^ t09;
            t12 = x3  ^ t04;
            t13 = x2  | t10;
            y3  = t03 ^ t12;
            t15 = x0  ^ t04;
            y2  = t11 ^ t13;
            y0  = t15 ^ t09;

            y0 ^=  K[28*4+0];  y1 ^=  K[28*4+1];   y2 ^=  K[28*4+2];  y3 ^=  K[28*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

            /* depth = 3,6,4,4, Total gates=17 */

            t01 = x2  | x3 ;
            t02 = x0  | x3 ;
            t03 = x2  ^ t02;
            t04 = x1  ^ t02;
            t05 = x0  ^ x3 ;
            t06 = t04 & t03;
            t07 = x1  & t01;
            y2  = t05 ^ t06;
            t09 = x0  ^ t03;
            y0  = t07 ^ t03;
            t11 = y0  | t05;
            t12 = t09 & t11;
            t13 = x0  & y2 ;
            t14 = t01 ^ t05;
            y1  = x1  ^ t12;
            t16 = x1  | t13;
            y3  = t14 ^ t16;

            y0 ^=  K[27*4+0];  y1 ^=  K[27*4+1];   y2 ^=  K[27*4+2];  y3 ^=  K[27*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

            /* depth = 3,6,8,3, Total gates=18 */

            t01 = x0  ^ x3 ;
            t02 = x2  ^ x3 ;
            t03 = x0  & x2 ;
            t04 = x1  | t02;
            y0  = t01 ^ t04;
            t06 = x0  | x2 ;
            t07 = x3  | y0 ;
            t08 =     ~ x3 ;
            t09 = x1  & t06;
            t10 = t08 | t03;
            t11 = x1  & t07;
            t12 = t06 & t02;
            y3  = t09 ^ t10;
            y1  = t12 ^ t11;
            t15 = x2  & y3 ;
            t16 = y0  ^ y1 ;
            t17 = t10 ^ t15;
            y2  = t16 ^ t17;

            y0 ^=  K[26*4+0];  y1 ^=  K[26*4+1];   y2 ^=  K[26*4+2];  y3 ^=  K[26*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

            /* depth = 7,4,5,3, Total gates=18 */

            t01 = x0  ^ x1 ;
            t02 = x1  | x3 ;
            t03 = x0  & x2 ;
            t04 = x2  ^ t02;
            t05 = x0  | t04;
            t06 = t01 & t05;
            t07 = x3  | t03;
            t08 = x1  ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3  & t08;
            y2  =     ~ t09;
            y1  = t10 ^ t11;
            t14 = x0  | y2 ;
            t15 = t06 ^ y1 ;
            y3  = t01 ^ t04;
            t17 = x2  ^ t15;
            y0  = t14 ^ t17;

            y0 ^=  K[25*4+0];  y1 ^=  K[25*4+1];   y2 ^=  K[25*4+2];  y3 ^=  K[25*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

            /* depth = 8,4,3,6, Total gates=19 */

            t01 = x2  ^ x3 ;
            t02 = x0  | x1 ;
            t03 = x1  | x2 ;
            t04 = x2  & t01;
            t05 = t02 ^ t01;
            t06 = x0  | t04;
            y2  =     ~ t05;
            t08 = x1  ^ x3 ;
            t09 = t03 & t08;
            t10 = x3  | y2 ;
            y1  = t09 ^ t06;
            t12 = x0  | t05;
            t13 = y1  ^ t12;
            t14 = t03 ^ t10;
            t15 = x0  ^ x2 ;
            y3  = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0  = t15 ^ t18;

            y0 ^=  K[24*4+0];  y1 ^=  K[24*4+1];   y2 ^=  K[24*4+2];  y3 ^=  K[24*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

            /* depth = 9,7,3,3, Total gates=18 */

            t01 = x0  & x1 ;
            t02 = x0  | x1 ;
            t03 = x2  | t01;
            t04 = x3  & t02;
            y3  = t03 ^ t04;
            t06 = x1  ^ t04;
            t07 = x3  ^ y3 ;
            t08 =     ~ t07;
            t09 = t06 | t08;
            t10 = x1  ^ x3 ;
            t11 = x0  | x3 ;
            y1  = x0  ^ t09;
            t13 = x2  ^ t06;
            t14 = x2  & t11;
            t15 = x3  | y1 ;
            t16 = t01 | t10;
            y0  = t13 ^ t15;
            y2  = t14 ^ t16;

            y0 ^=  K[23*4+0];  y1 ^=  K[23*4+1];   y2 ^=  K[23*4+2];  y3 ^=  K[23*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

            /* depth = 5,3,8,6, Total gates=19 */

            t01 = x0  ^ x2 ;
            t02 =     ~ x2 ;
            t03 = x1  & t01;
            t04 = x1  | t02;
            t05 = x3  | t03;
            t06 = x1  ^ x3 ;
            t07 = x0  & t04;
            t08 = x0  | t02;
            t09 = t07 ^ t05;
            y1  = t06 ^ t08;
            y0  =     ~ t09;
            t12 = x1  & y0 ;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3  | t02;
            t17 = x0  ^ y1 ;
            y3  = t17 ^ t15;
            y2  = t16 ^ t14;

            y0 ^=  K[22*4+0];  y1 ^=  K[22*4+1];   y2 ^=  K[22*4+2];  y3 ^=  K[22*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

            /* depth = 4,6,9,7, Total gates=17 */

            t01 = x0  & x3 ;
            t02 = x2  ^ t01;
            t03 = x0  ^ x3 ;
            t04 = x1  & t02;
            t05 = x0  & x2 ;
            y0  = t03 ^ t04;
            t07 = x0  & y0 ;
            t08 = t01 ^ y0 ;
            t09 = x1  | t05;
            t10 =     ~ x1 ;
            y1  = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0  | y1 ;
            y3  = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1  ^ x3 ;
            y2  = t16 ^ t15;

            y0 ^=  K[21*4+0];  y1 ^=  K[21*4+1];   y2 ^=  K[21*4+2];  y3 ^=  K[21*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

            /* depth = 6,4,7,3, Total gates=17 */

            t01 = x1  | x3 ;
            t02 = x2  | x3 ;
            t03 = x0  & t01;
            t04 = x1  ^ t02;
            t05 = x2  ^ x3 ;
            t06 =     ~ t03;
            t07 = x0  & t04;
            y1  = t05 ^ t07;
            t09 = y1  | t06;
            t10 = x0  ^ t07;
            t11 = t01 ^ t09;
            t12 = x3  ^ t04;
            t13 = x2  | t10;
            y3  = t03 ^ t12;
            t15 = x0  ^ t04;
            y2  = t11 ^ t13;
            y0  = t15 ^ t09;

            y0 ^=  K[20*4+0];  y1 ^=  K[20*4+1];   y2 ^=  K[20*4+2];  y3 ^=  K[20*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

            /* depth = 3,6,4,4, Total gates=17 */

            t01 = x2  | x3 ;
            t02 = x0  | x3 ;
            t03 = x2  ^ t02;
            t04 = x1  ^ t02;
            t05 = x0  ^ x3 ;
            t06 = t04 & t03;
            t07 = x1  & t01;
            y2  = t05 ^ t06;
            t09 = x0  ^ t03;
            y0  = t07 ^ t03;
            t11 = y0  | t05;
            t12 = t09 & t11;
            t13 = x0  & y2 ;
            t14 = t01 ^ t05;
            y1  = x1  ^ t12;
            t16 = x1  | t13;
            y3  = t14 ^ t16;

            y0 ^=  K[19*4+0];  y1 ^=  K[19*4+1];   y2 ^=  K[19*4+2];  y3 ^=  K[19*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

            /* depth = 3,6,8,3, Total gates=18 */

            t01 = x0  ^ x3 ;
            t02 = x2  ^ x3 ;
            t03 = x0  & x2 ;
            t04 = x1  | t02;
            y0  = t01 ^ t04;
            t06 = x0  | x2 ;
            t07 = x3  | y0 ;
            t08 =     ~ x3 ;
            t09 = x1  & t06;
            t10 = t08 | t03;
            t11 = x1  & t07;
            t12 = t06 & t02;
            y3  = t09 ^ t10;
            y1  = t12 ^ t11;
            t15 = x2  & y3 ;
            t16 = y0  ^ y1 ;
            t17 = t10 ^ t15;
            y2  = t16 ^ t17;

            y0 ^=  K[18*4+0];  y1 ^=  K[18*4+1];   y2 ^=  K[18*4+2];  y3 ^=  K[18*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

            /* depth = 7,4,5,3, Total gates=18 */

            t01 = x0  ^ x1 ;
            t02 = x1  | x3 ;
            t03 = x0  & x2 ;
            t04 = x2  ^ t02;
            t05 = x0  | t04;
            t06 = t01 & t05;
            t07 = x3  | t03;
            t08 = x1  ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3  & t08;
            y2  =     ~ t09;
            y1  = t10 ^ t11;
            t14 = x0  | y2 ;
            t15 = t06 ^ y1 ;
            y3  = t01 ^ t04;
            t17 = x2  ^ t15;
            y0  = t14 ^ t17;

            y0 ^=  K[17*4+0];  y1 ^=  K[17*4+1];   y2 ^=  K[17*4+2];  y3 ^=  K[17*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

            /* depth = 8,4,3,6, Total gates=19 */

            t01 = x2  ^ x3 ;
            t02 = x0  | x1 ;
            t03 = x1  | x2 ;
            t04 = x2  & t01;
            t05 = t02 ^ t01;
            t06 = x0  | t04;
            y2  =     ~ t05;
            t08 = x1  ^ x3 ;
            t09 = t03 & t08;
            t10 = x3  | y2 ;
            y1  = t09 ^ t06;
            t12 = x0  | t05;
            t13 = y1  ^ t12;
            t14 = t03 ^ t10;
            t15 = x0  ^ x2 ;
            y3  = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0  = t15 ^ t18;

            y0 ^=  K[16*4+0];  y1 ^=  K[16*4+1];   y2 ^=  K[16*4+2];  y3 ^=  K[16*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

            /* depth = 9,7,3,3, Total gates=18 */

            t01 = x0  & x1 ;
            t02 = x0  | x1 ;
            t03 = x2  | t01;
            t04 = x3  & t02;
            y3  = t03 ^ t04;
            t06 = x1  ^ t04;
            t07 = x3  ^ y3 ;
            t08 =     ~ t07;
            t09 = t06 | t08;
            t10 = x1  ^ x3 ;
            t11 = x0  | x3 ;
            y1  = x0  ^ t09;
            t13 = x2  ^ t06;
            t14 = x2  & t11;
            t15 = x3  | y1 ;
            t16 = t01 | t10;
            y0  = t13 ^ t15;
            y2  = t14 ^ t16;

            y0 ^=  K[15*4+0];  y1 ^=  K[15*4+1];   y2 ^=  K[15*4+2];  y3 ^=  K[15*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

            /* depth = 5,3,8,6, Total gates=19 */

            t01 = x0  ^ x2 ;
            t02 =     ~ x2 ;
            t03 = x1  & t01;
            t04 = x1  | t02;
            t05 = x3  | t03;
            t06 = x1  ^ x3 ;
            t07 = x0  & t04;
            t08 = x0  | t02;
            t09 = t07 ^ t05;
            y1  = t06 ^ t08;
            y0  =     ~ t09;
            t12 = x1  & y0 ;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3  | t02;
            t17 = x0  ^ y1 ;
            y3  = t17 ^ t15;
            y2  = t16 ^ t14;

            y0 ^=  K[14*4+0];  y1 ^=  K[14*4+1];   y2 ^=  K[14*4+2];  y3 ^=  K[14*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

            /* depth = 4,6,9,7, Total gates=17 */

            t01 = x0  & x3 ;
            t02 = x2  ^ t01;
            t03 = x0  ^ x3 ;
            t04 = x1  & t02;
            t05 = x0  & x2 ;
            y0  = t03 ^ t04;
            t07 = x0  & y0 ;
            t08 = t01 ^ y0 ;
            t09 = x1  | t05;
            t10 =     ~ x1 ;
            y1  = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0  | y1 ;
            y3  = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1  ^ x3 ;
            y2  = t16 ^ t15;

            y0 ^=  K[13*4+0];  y1 ^=  K[13*4+1];   y2 ^=  K[13*4+2];  y3 ^=  K[13*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

            /* depth = 6,4,7,3, Total gates=17 */

            t01 = x1  | x3 ;
            t02 = x2  | x3 ;
            t03 = x0  & t01;
            t04 = x1  ^ t02;
            t05 = x2  ^ x3 ;
            t06 =     ~ t03;
            t07 = x0  & t04;
            y1  = t05 ^ t07;
            t09 = y1  | t06;
            t10 = x0  ^ t07;
            t11 = t01 ^ t09;
            t12 = x3  ^ t04;
            t13 = x2  | t10;
            y3  = t03 ^ t12;
            t15 = x0  ^ t04;
            y2  = t11 ^ t13;
            y0  = t15 ^ t09;

            y0 ^=  K[12*4+0];  y1 ^=  K[12*4+1];   y2 ^=  K[12*4+2];  y3 ^=  K[12*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

            /* depth = 3,6,4,4, Total gates=17 */

            t01 = x2  | x3 ;
            t02 = x0  | x3 ;
            t03 = x2  ^ t02;
            t04 = x1  ^ t02;
            t05 = x0  ^ x3 ;
            t06 = t04 & t03;
            t07 = x1  & t01;
            y2  = t05 ^ t06;
            t09 = x0  ^ t03;
            y0  = t07 ^ t03;
            t11 = y0  | t05;
            t12 = t09 & t11;
            t13 = x0  & y2 ;
            t14 = t01 ^ t05;
            y1  = x1  ^ t12;
            t16 = x1  | t13;
            y3  = t14 ^ t16;

            y0 ^=  K[11*4+0];  y1 ^=  K[11*4+1];   y2 ^=  K[11*4+2];  y3 ^=  K[11*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

            /* depth = 3,6,8,3, Total gates=18 */

            t01 = x0  ^ x3 ;
            t02 = x2  ^ x3 ;
            t03 = x0  & x2 ;
            t04 = x1  | t02;
            y0  = t01 ^ t04;
            t06 = x0  | x2 ;
            t07 = x3  | y0 ;
            t08 =     ~ x3 ;
            t09 = x1  & t06;
            t10 = t08 | t03;
            t11 = x1  & t07;
            t12 = t06 & t02;
            y3  = t09 ^ t10;
            y1  = t12 ^ t11;
            t15 = x2  & y3 ;
            t16 = y0  ^ y1 ;
            t17 = t10 ^ t15;
            y2  = t16 ^ t17;

            y0 ^=  K[10*4+0];  y1 ^=  K[10*4+1];   y2 ^=  K[10*4+2];  y3 ^=  K[10*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

            /* depth = 7,4,5,3, Total gates=18 */

            t01 = x0  ^ x1 ;
            t02 = x1  | x3 ;
            t03 = x0  & x2 ;
            t04 = x2  ^ t02;
            t05 = x0  | t04;
            t06 = t01 & t05;
            t07 = x3  | t03;
            t08 = x1  ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3  & t08;
            y2  =     ~ t09;
            y1  = t10 ^ t11;
            t14 = x0  | y2 ;
            t15 = t06 ^ y1 ;
            y3  = t01 ^ t04;
            t17 = x2  ^ t15;
            y0  = t14 ^ t17;

            y0 ^=  K[ 9*4+0];  y1 ^=  K[ 9*4+1];   y2 ^=  K[ 9*4+2];  y3 ^=  K[ 9*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

            /* depth = 8,4,3,6, Total gates=19 */

            t01 = x2  ^ x3 ;
            t02 = x0  | x1 ;
            t03 = x1  | x2 ;
            t04 = x2  & t01;
            t05 = t02 ^ t01;
            t06 = x0  | t04;
            y2  =     ~ t05;
            t08 = x1  ^ x3 ;
            t09 = t03 & t08;
            t10 = x3  | y2 ;
            y1  = t09 ^ t06;
            t12 = x0  | t05;
            t13 = y1  ^ t12;
            t14 = t03 ^ t10;
            t15 = x0  ^ x2 ;
            y3  = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0  = t15 ^ t18;

            y0 ^=  K[ 8*4+0];  y1 ^=  K[ 8*4+1];   y2 ^=  K[ 8*4+2];  y3 ^=  K[ 8*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

            /* depth = 9,7,3,3, Total gates=18 */

            t01 = x0  & x1 ;
            t02 = x0  | x1 ;
            t03 = x2  | t01;
            t04 = x3  & t02;
            y3  = t03 ^ t04;
            t06 = x1  ^ t04;
            t07 = x3  ^ y3 ;
            t08 =     ~ t07;
            t09 = t06 | t08;
            t10 = x1  ^ x3 ;
            t11 = x0  | x3 ;
            y1  = x0  ^ t09;
            t13 = x2  ^ t06;
            t14 = x2  & t11;
            t15 = x3  | y1 ;
            t16 = t01 | t10;
            y0  = t13 ^ t15;
            y2  = t14 ^ t16;

            y0 ^=  K[ 7*4+0];  y1 ^=  K[ 7*4+1];   y2 ^=  K[ 7*4+2];  y3 ^=  K[ 7*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

            /* depth = 5,3,8,6, Total gates=19 */

            t01 = x0  ^ x2 ;
            t02 =     ~ x2 ;
            t03 = x1  & t01;
            t04 = x1  | t02;
            t05 = x3  | t03;
            t06 = x1  ^ x3 ;
            t07 = x0  & t04;
            t08 = x0  | t02;
            t09 = t07 ^ t05;
            y1  = t06 ^ t08;
            y0  =     ~ t09;
            t12 = x1  & y0 ;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3  | t02;
            t17 = x0  ^ y1 ;
            y3  = t17 ^ t15;
            y2  = t16 ^ t14;

            y0 ^=  K[ 6*4+0];  y1 ^=  K[ 6*4+1];   y2 ^=  K[ 6*4+2];  y3 ^=  K[ 6*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

            /* depth = 4,6,9,7, Total gates=17 */

            t01 = x0  & x3 ;
            t02 = x2  ^ t01;
            t03 = x0  ^ x3 ;
            t04 = x1  & t02;
            t05 = x0  & x2 ;
            y0  = t03 ^ t04;
            t07 = x0  & y0 ;
            t08 = t01 ^ y0 ;
            t09 = x1  | t05;
            t10 =     ~ x1 ;
            y1  = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0  | y1 ;
            y3  = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1  ^ x3 ;
            y2  = t16 ^ t15;

            y0 ^=  K[ 5*4+0];  y1 ^=  K[ 5*4+1];   y2 ^=  K[ 5*4+2];  y3 ^=  K[ 5*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

            /* depth = 6,4,7,3, Total gates=17 */

            t01 = x1  | x3 ;
            t02 = x2  | x3 ;
            t03 = x0  & t01;
            t04 = x1  ^ t02;
            t05 = x2  ^ x3 ;
            t06 =     ~ t03;
            t07 = x0  & t04;
            y1  = t05 ^ t07;
            t09 = y1  | t06;
            t10 = x0  ^ t07;
            t11 = t01 ^ t09;
            t12 = x3  ^ t04;
            t13 = x2  | t10;
            y3  = t03 ^ t12;
            t15 = x0  ^ t04;
            y2  = t11 ^ t13;
            y0  = t15 ^ t09;

            y0 ^=  K[ 4*4+0];  y1 ^=  K[ 4*4+1];   y2 ^=  K[ 4*4+2];  y3 ^=  K[ 4*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

            /* depth = 3,6,4,4, Total gates=17 */

            t01 = x2  | x3 ;
            t02 = x0  | x3 ;
            t03 = x2  ^ t02;
            t04 = x1  ^ t02;
            t05 = x0  ^ x3 ;
            t06 = t04 & t03;
            t07 = x1  & t01;
            y2  = t05 ^ t06;
            t09 = x0  ^ t03;
            y0  = t07 ^ t03;
            t11 = y0  | t05;
            t12 = t09 & t11;
            t13 = x0  & y2 ;
            t14 = t01 ^ t05;
            y1  = x1  ^ t12;
            t16 = x1  | t13;
            y3  = t14 ^ t16;

            y0 ^=  K[ 3*4+0];  y1 ^=  K[ 3*4+1];   y2 ^=  K[ 3*4+2];  y3 ^=  K[ 3*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

            /* depth = 3,6,8,3, Total gates=18 */

            t01 = x0  ^ x3 ;
            t02 = x2  ^ x3 ;
            t03 = x0  & x2 ;
            t04 = x1  | t02;
            y0  = t01 ^ t04;
            t06 = x0  | x2 ;
            t07 = x3  | y0 ;
            t08 =     ~ x3 ;
            t09 = x1  & t06;
            t10 = t08 | t03;
            t11 = x1  & t07;
            t12 = t06 & t02;
            y3  = t09 ^ t10;
            y1  = t12 ^ t11;
            t15 = x2  & y3 ;
            t16 = y0  ^ y1 ;
            t17 = t10 ^ t15;
            y2  = t16 ^ t17;

            y0 ^=  K[ 2*4+0];  y1 ^=  K[ 2*4+1];   y2 ^=  K[ 2*4+2];  y3 ^=  K[ 2*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

            /* depth = 7,4,5,3, Total gates=18 */

            t01 = x0  ^ x1 ;
            t02 = x1  | x3 ;
            t03 = x0  & x2 ;
            t04 = x2  ^ t02;
            t05 = x0  | t04;
            t06 = t01 & t05;
            t07 = x3  | t03;
            t08 = x1  ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3  & t08;
            y2  =     ~ t09;
            y1  = t10 ^ t11;
            t14 = x0  | y2 ;
            t15 = t06 ^ y1 ;
            y3  = t01 ^ t04;
            t17 = x2  ^ t15;
            y0  = t14 ^ t17;

            y0 ^=  K[ 1*4+0];  y1 ^=  K[ 1*4+1];   y2 ^=  K[ 1*4+2];  y3 ^=  K[ 1*4+3] ;
            x2  = ((((   y2  ))<<(32-(  22 )))| (((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (((   x0  ))>>(  13 )))  ;

            /* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

            /* depth = 8,4,3,6, Total gates=19 */

            t01 = x2  ^ x3 ;
            t02 = x0  | x1 ;
            t03 = x1  | x2 ;
            t04 = x2  & t01;
            t05 = t02 ^ t01;
            t06 = x0  | t04;
            y2  =     ~ t05;
            t08 = x1  ^ x3 ;
            t09 = t03 & t08;
            t10 = x3  | y2 ;
            y1  = t09 ^ t06;
            t12 = x0  | t05;
            t13 = y1  ^ t12;
            t14 = t03 ^ t10;
            t15 = x0  ^ x2 ;
            y3  = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0  = t15 ^ t18;

            x0 = y0; x1 = y1; x2 = y2; x3 = y3;
            x0 ^=  K[ 0*4+0];  x1 ^=  K[ 0*4+1];   x2 ^=  K[ 0*4+2];  x3 ^=  K[ 0*4+3] ;


            output[15] = (byte)(x0 & 0xFF);
            output[14] = (byte)((x0 >> 8) & 0xFF);
            output[13] = (byte)((x0 >> 16) & 0xFF);
            output[12] = (byte)((x0 >> 24) & 0xFF);

            output[11] = (byte)(x1 & 0xFF);
            output[10] = (byte)((x1 >> 8) & 0xFF);
            output[9] = (byte)((x1 >> 16) & 0xFF);
            output[8] = (byte)((x1 >> 24) & 0xFF);

            output[7] = (byte)(x2 & 0xFF);
            output[6] = (byte)((x2 >> 8) & 0xFF);
            output[5] = (byte)((x2 >> 16) & 0xFF);
            output[4] = (byte)((x2 >> 24) & 0xFF);

            output[3] = (byte)(x3 & 0xFF);
            output[2] = (byte)((x3 >> 8) & 0xFF);
            output[1] = (byte)((x3 >> 16) & 0xFF);
            output[0] = (byte)((x3 >> 24) & 0xFF);  
        }
        #endregion


    }


    #endregion
}
