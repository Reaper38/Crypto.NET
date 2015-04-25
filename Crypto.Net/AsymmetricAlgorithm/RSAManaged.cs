// Modified by Nils Reimers for CryptoNet

//
// RSAManaged.cs - Implements the RSA algorithm.
//
// Authors:
//	Sebastien Pouliot (sebastien@ximian.com)
//	Ben Maurer (bmaurer@users.sf.net)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Portions (C) 2003 Ben Maurer
// Copyright (C) 2004,2006 Novell, Inc (http://www.novell.com)
//
// Key generation translated from Bouncy Castle JCE (http://www.bouncycastle.org/)
// See bouncycastle.txt for license.
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
//

using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;


namespace CryptoNet
{

	public class RSAManaged : RSA {

		private const int defaultKeySize = 1024;
        private const uint uint_e = 65537;

		private bool isCRTpossible = false;
		
		private bool keypairGenerated = false;
		private bool m_disposed = false;

		private BigInteger d;
		private BigInteger p;
		private BigInteger q;
		private BigInteger dp;
		private BigInteger dq;
		private BigInteger qInv;
		private BigInteger n;		// modulus
		private BigInteger e;

		public RSAManaged () : this (defaultKeySize)
		{
		}

		public RSAManaged (int keySize) 
		{
			LegalKeySizesValue = new KeySizes [1];
			LegalKeySizesValue [0] = new KeySizes (384, 16384, 8);
			base.KeySize = keySize;
            
		}

        ~RSAManaged() 
		{
			// Zeroize private key
			Dispose (false);
		}

		private void GenerateKeyPair () 
		{
			// p and q values should have a length of half the strength in bits
			int pbitlength = ((KeySize + 1) >> 1);
			int qbitlength = (KeySize - pbitlength);
			
			e = uint_e; // fixed
	
			// generate p, prime and (p-1) relatively prime to e
			for (;;) {
				p = BigInteger.GeneratePseudoPrime (pbitlength);
				if (p % uint_e != 1)
					break;
			}
			// generate a modulus of the required length
			for (;;) {
				// generate q, prime and (q-1) relatively prime to e,
				// and not equal to p
				for (;;) {
					q = BigInteger.GeneratePseudoPrime (qbitlength);
					if ((q % uint_e != 1) && (p != q))
						break;
				}
	
				// calculate the modulus
				n = p * q;
				if (n.BitCount () == KeySize)
					break;
	
				// if we get here our primes aren't big enough, make the largest
				// of the two p and try again
				if (p < q)
					p = q;
			}
	
			BigInteger pSub1 = (p - 1);
			BigInteger qSub1 = (q - 1);
			BigInteger phi = pSub1 * qSub1;
	
			// calculate the private exponent
			d = e.ModInverse (phi);
	
			// calculate the CRT factors
			dp = d % pSub1;
			dq = d % qSub1;
			qInv = q.ModInverse (p);
	
			keypairGenerated = true;
			isCRTpossible = true;

            Thread checkPrimes = new Thread(new ThreadStart(CheckPrimeNumbers));
            checkPrimes.IsBackground = true;
            checkPrimes.Priority = ThreadPriority.Lowest;
            checkPrimes.Start();

			if (KeyGenerated != null)
				KeyGenerated (this, null);
		}
		
		// overrides from RSA class

		public override int KeySize {
			get { 
				// in case keypair hasn't been (yet) generated
				if (keypairGenerated) {
					int ks = n.BitCount ();
					if ((ks & 7) != 0)
						ks = ks + (8 - (ks & 7));
					return ks;
				}
				else
					return base.KeySize;
			}
		}
		public override string KeyExchangeAlgorithm {
			get { return "RSA-PKCS1-KeyEx"; }
		}

		// note: when (if) we generate a keypair then it will have both
		// the public and private keys
		public bool PublicOnly {
			get { return (keypairGenerated && ((d == null) || (n == null))); }
		}

		public override string SignatureAlgorithm {
			get { return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; }
		}


        /// <summary>
        /// Decrypts a value
        /// </summary>   
        public override byte[] DecryptValue(byte[] rgb)
        {
            return DecryptValue(rgb, false);
        }

        /// <summary>
        /// Decrypts a value
        /// </summary>
        /// <param name="rgb">Encrypted data</param>
        /// <param name="usedPadding">if the data is encrypted with padding (recommended) it has to be true.
        /// If the value isn't encrypted by this implementation, it has to be false</param>
        /// <returns></returns>
		public byte[] DecryptValue (byte[] rgb, bool usedPadding) 
		{
			if (m_disposed)
				throw new ObjectDisposedException ("private key");

			// decrypt operation is used for signature
			if (!keypairGenerated)
				GenerateKeyPair ();

			BigInteger input = new BigInteger (rgb);
			BigInteger r = null;

			// we use key blinding (by default) against timing attacks
			
			// x = (r^e * g) mod n 
			// *new* random number (so it's timing is also random)
			r = BigInteger.GenerateRandom (n.BitCount ());
			input = r.ModPow (e, n) * input % n;
			

			BigInteger output;
			// decrypt (which uses the private key) can be 
			// optimized by using CRT (Chinese Remainder Theorem)
			if (isCRTpossible) {
				// m1 = c^dp mod p
				BigInteger m1 = input.ModPow (dp, p);
				// m2 = c^dq mod q
				BigInteger m2 = input.ModPow (dq, q);
				BigInteger h;
				if (m2 > m1) {
					// thanks to benm!
					h = p - ((m2 - m1) * qInv % p);
					output = m2 + q * h;
				} else {
					// h = (m1 - m2) * qInv mod p
					h = (m1 - m2) * qInv % p;
					// m = m2 + q * h;
					output = m2 + q * h;
				}
			} else if (!PublicOnly) {
				// m = c^d mod n
				output = input.ModPow (d, n);
			} else {
				throw new CryptographicException (("Missing private key to decrypt value."));
			}

			
			// Complete blinding
			// x^e / r mod n
			output = output * r.ModInverse (n) % n;
			r.Clear ();




            byte[] result;
            byte[] tmp;
            if (usedPadding)
            {
                tmp = output.GetBytes();
                result = new byte[tmp.Length - 1];

                //Remove the first byte of tmp (plain), because it is the padding
                Buffer.BlockCopy(tmp, 1, result, 0, result.Length);
            }
            else
                result = GetPaddedValue (output);
              
          
            tmp = null;

			// zeroize values
			input.Clear ();	
			output.Clear ();
			return result;
		}


        /// <summary>
        /// Encrypts the value rgb
        /// </summary>        
        public override byte[] EncryptValue(byte[] rgb)
        {            
            return EncryptValue(rgb, false);
        }

        /// <summary>
        /// Encrypts the value rgb
        /// </summary>
        /// <param name="rgb">Data for encryption</param>
        /// <param name="usingPadding">should be true (recommended), so that rgb can restore exactly. 
        /// if usingPadding is false, 0x00-bytes can be missed when you decrypt the cipher, 
        /// but with usingPadding=false it is compatible with other RSA-Implementations.   </param>
        /// 
        /// <returns></returns>
		public byte[] EncryptValue (byte[] rgb, bool usingPadding) 
		{
			if (m_disposed)
				throw new ObjectDisposedException ("public key");

			if (!keypairGenerated)
				GenerateKeyPair ();

            if (usingPadding && (rgb.Length + 1) > (KeySize >> 3))
                throw new CryptographicException("rgb is to long, maximal " + ((KeySize >> 3) - 1) + " bytes");

            byte[] data;

            //Insert 0x0000...01 in front of the message
            //so you can later determine at which byte
            //the orginale message starts

            if (usingPadding)
            {
                data = new byte[KeySize >> 3];
                data[data.Length - rgb.Length - 1] = 0x01;
                Buffer.BlockCopy(rgb, 0, data, data.Length - rgb.Length, rgb.Length);
            }
            else
                data = rgb;
            
            
			BigInteger input = new BigInteger (data);

            if (input >= n)
                throw new CryptographicException("rgb is to long");

			BigInteger output = input.ModPow (e, n);

            byte[] result;
            /*
            if(!usingPadding)
                result = GetPaddedValue (output);
            else
                result = output.GetBytes();
             */

            result = GetPaddedValue(output);
            // zeroize value
			input.Clear ();	
			output.Clear ();
			return result;
		}

		public override RSAParameters ExportParameters (bool includePrivateParameters) 
		{
			if (m_disposed)
				throw new ObjectDisposedException ("");

			if (!keypairGenerated)
				GenerateKeyPair ();
	
			RSAParameters param = new RSAParameters ();
			param.Exponent = e.GetBytes ();
			param.Modulus = n.GetBytes ();
			if (includePrivateParameters) {
				// some parameters are required for exporting the private key
				if (d == null)
					throw new CryptographicException ("Missing private key");
				param.D = d.GetBytes ();
				// hack for bugzilla #57941 where D wasn't provided
				if (param.D.Length != param.Modulus.Length) {
					byte[] normalizedD = new byte [param.Modulus.Length];
					Buffer.BlockCopy (param.D, 0, normalizedD, (normalizedD.Length - param.D.Length), param.D.Length);
					param.D = normalizedD;
				}
				// but CRT parameters are optionals
				if ((p != null) && (q != null) && (dp != null) && (dq != null) && (qInv != null)) {
					// and we include them only if we have them all
					param.P = p.GetBytes ();
					param.Q = q.GetBytes ();
					param.DP = dp.GetBytes ();
					param.DQ = dq.GetBytes ();
					param.InverseQ = qInv.GetBytes ();
				}
			}
			return param;
		}

		public override void ImportParameters (RSAParameters parameters) 
		{
			if (m_disposed)
				throw new ObjectDisposedException ("");

			// if missing "mandatory" parameters
			if (parameters.Exponent == null) 
				throw new CryptographicException ("Missing Exponent");
			if (parameters.Modulus == null)
				throw new CryptographicException ("Missing Modulus");
	
			e = new BigInteger (parameters.Exponent);
			n = new BigInteger (parameters.Modulus);
			// only if the private key is present
			if (parameters.D != null)
				d = new BigInteger (parameters.D);
			if (parameters.DP != null)
				dp = new BigInteger (parameters.DP);
			if (parameters.DQ != null)
				dq = new BigInteger (parameters.DQ);
			if (parameters.InverseQ != null)
				qInv = new BigInteger (parameters.InverseQ);
			if (parameters.P != null)
				p = new BigInteger (parameters.P);
			if (parameters.Q != null)
				q = new BigInteger (parameters.Q);
			
			// we now have a keypair
			keypairGenerated = true;
			isCRTpossible = ((p != null) && (q != null) && (dp != null) && (dq != null) && (qInv != null));
		}

		protected override void Dispose (bool disposing) 
		{
			if (!m_disposed) {
				// Always zeroize private key
				if (d != null) {
					d.Clear (); 
					d = null;
				}
				if (p != null) {
					p.Clear (); 
					p = null;
				}
				if (q != null) {
					q.Clear (); 
					q = null;
				}
				if (dp != null) {
					dp.Clear (); 
					dp = null;
				}
				if (dq != null) {
					dq.Clear (); 
					dq = null;
				}
				if (qInv != null) {
					qInv.Clear (); 
					qInv = null;
				}

				if (disposing) {
					// clear public key
					if (e != null) {
						e.Clear (); 
						e = null;
					}
					if (n != null) {
						n.Clear (); 
						n = null;
					}
				}
			}
			// call base class 
			// no need as they all are abstract before us
			m_disposed = true;
		}

		public delegate void KeyGeneratedEventHandler (object sender, EventArgs e);

		public event KeyGeneratedEventHandler KeyGenerated;

		public override string ToXmlString (bool includePrivateParameters) 
		{
			StringBuilder sb = new StringBuilder ();
			RSAParameters rsaParams = ExportParameters (includePrivateParameters);
			try {
				sb.Append ("<RSAKeyValue>");
				
				sb.Append ("<Modulus>");
				sb.Append (Convert.ToBase64String (rsaParams.Modulus));
				sb.Append ("</Modulus>");

				sb.Append ("<Exponent>");
				sb.Append (Convert.ToBase64String (rsaParams.Exponent));
				sb.Append ("</Exponent>");

				if (includePrivateParameters) {
					if (rsaParams.P != null) {
						sb.Append ("<P>");
						sb.Append (Convert.ToBase64String (rsaParams.P));
						sb.Append ("</P>");
					}
					if (rsaParams.Q != null) {
						sb.Append ("<Q>");
						sb.Append (Convert.ToBase64String (rsaParams.Q));
						sb.Append ("</Q>");
					}
					if (rsaParams.DP != null) {
						sb.Append ("<DP>");
						sb.Append (Convert.ToBase64String (rsaParams.DP));
						sb.Append ("</DP>");
					}
					if (rsaParams.DQ != null) {
						sb.Append ("<DQ>");
						sb.Append (Convert.ToBase64String (rsaParams.DQ));
						sb.Append ("</DQ>");
					}
					if (rsaParams.InverseQ != null) {
						sb.Append ("<InverseQ>");
						sb.Append (Convert.ToBase64String (rsaParams.InverseQ));
						sb.Append ("</InverseQ>");
					}
					sb.Append ("<D>");
					sb.Append (Convert.ToBase64String (rsaParams.D));
					sb.Append ("</D>");
				}
				
				sb.Append ("</RSAKeyValue>");
			}
			catch {
				if (rsaParams.P != null)
					Array.Clear (rsaParams.P, 0, rsaParams.P.Length);
				if (rsaParams.Q != null)
					Array.Clear (rsaParams.Q, 0, rsaParams.Q.Length);
				if (rsaParams.DP != null)
					Array.Clear (rsaParams.DP, 0, rsaParams.DP.Length);
				if (rsaParams.DQ != null)
					Array.Clear (rsaParams.DQ, 0, rsaParams.DQ.Length);
				if (rsaParams.InverseQ != null)
					Array.Clear (rsaParams.InverseQ, 0, rsaParams.InverseQ.Length);
				if (rsaParams.D != null)
					Array.Clear (rsaParams.D, 0, rsaParams.D.Length);
				throw;
			}
			
			return sb.ToString ();
		}

		public bool IsCrtPossible {
			// either the key pair isn't generated (and will be 
			// generated with CRT parameters) or CRT is (or isn't)
			// possible (in case the key was imported)
			get { return (!keypairGenerated || isCRTpossible); }
		}

		private byte[] GetPaddedValue (BigInteger value)
		{
			byte[] result = value.GetBytes ();
			int length = (KeySize >> 3);
			if (result.Length >= length)
				return result;

			// left-pad 0x00 value on the result (same integer, correct length)
			byte[] padded = new byte[length];
			Buffer.BlockCopy (result, 0, padded, (length - result.Length), result.Length);
			// temporary result may contain decrypted (plaintext) data, clear it
			Array.Clear (result, 0, result.Length);
			return padded;
		}

        /// <summary>
        /// Make sure that p and q are realy strong prime numbers
        /// </summary>
        private void CheckPrimeNumbers()
        {
            if (!PrimalityTests.RabinMillerTest(p, 20) || !PrimalityTests.RabinMillerTest(q, 20))            
                keypairGenerated = isCRTpossible = false;               
            
        }
	}
}
