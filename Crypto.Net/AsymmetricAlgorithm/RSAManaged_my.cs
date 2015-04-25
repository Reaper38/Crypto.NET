using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;



namespace CryptoSharp
{
    public class RSAManaged_my
    {
        public event EventHandler KeyGenerated;

        private const uint e_fixed = 65537;
        private BigInteger e = new BigInteger(e_fixed);
        private BigInteger n;
        private BigInteger p, q;
        private BigInteger d;
        private BigInteger dp, dq;
        private BigInteger qInv;

        private bool keyGenerated = false;
        private bool CRT = false;

        public RSAManaged_my()
            : this(1024)
        {
        }

        public RSAManaged_my(int keySize)
        {   
            GenerateRandomKey(keySize);            
        }

        ~RSAManaged_my() 
		{
            DeletePrivateKey();
            DeletePublicKey();
        }


        public byte[] EncryptValue(byte[] rgb)
        {

            if (n == null)
                throw new NullReferenceException("Missing public key");

            BigInteger plain = new BigInteger(rgb);
            BigInteger cipher = plain.ModPow(e, n);
       
            plain.Clear();
         
            return cipher.GetBytes();
        }

      

        protected void GenerateRandomKey(int keySize)
        {           

            //Generating p
            while(true)
            {
                p = BigInteger.GeneratePseudoPrime(keySize>>1);
                if (p % e_fixed != 1)
                    break;
            }

                       
            while(true)
            {
                //Generating q 
                while (true)
                {
                    q = BigInteger.GeneratePseudoPrime(keySize >> 1);
                    if ((q % e_fixed != 1) && (p != q))
                        break;
                }

                //Modulus n
                n = p * q;

                if (n.BitCount() == keySize)
                    break;

                if (p < q)
                    p = q;
            }
            
            //Private Key
            BigInteger pSub1 = (p - 1);
            BigInteger qSub1 = (q - 1);
            BigInteger phi = pSub1 * qSub1;
            d = e.ModInverse(phi);

            dp = d % pSub1;
            dq = d % qSub1;
            qInv = q.ModInverse(p);

            keyGenerated = CRT = true;
            
            if (KeyGenerated != null)
                KeyGenerated(this, EventArgs.Empty);
          
            
            Thread checkPrimes = new Thread(new ThreadStart(CheckPrimeNumbers));
            checkPrimes.IsBackground = true;
            checkPrimes.Start();
        }

        protected void CheckPrimeNumbers()
        {
            if (!PrimalityTests.RabinMillerTest(p, 40) || !PrimalityTests.RabinMillerTest(q, 40))
            {
                keyGenerated = CRT = false;
                DeletePrivateKey();
                DeletePublicKey();
            }
        }

        private void DeletePrivateKey()
        {
            if (d != null)
            {
                d.Clear();
                d = null;
            }
            if (p != null)
            {
                p.Clear();
                p = null;
            }
            if (q != null)
            {
                q.Clear();
                q = null;
            }
            if (dp != null)
            {
                dp.Clear();
                dp = null;
            }
            if (dq != null)
            {
                dq.Clear();
                dq = null;
            }
            if (qInv != null)
            {
                qInv.Clear();
                qInv = null;
            }           
        }

        private void DeletePublicKey()
        {
            n = null;
        }
    }
}
