// SslServerStream.cs - A wrapper for the Mono.SslServerStream class

//============================================================================
// CryptoSharp - A cryptography library for C#
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
using System.IO;

using System.Security.Cryptography.X509Certificates;




namespace CryptoSharp.SSL
{
    public class SslServerStream : Tls.SslServerStream
    {
        private const string beginToken = "-----BEGIN RSA PRIVATE KEY-----";
        private const string endToken = "-----END RSA PRIVATE KEY-----";

        private byte[] privateKey;

        #region Properties
        public byte[] PrivateKey
        {
            get { return privateKey; }
            set { privateKey = value; }
        }        
        #endregion

        #region Constructor
        public SslServerStream(Stream stream, X509Certificate serverCertificate)
            : base(stream, serverCertificate)
        {
            Initialize();
        }

        public SslServerStream(Stream stream, X509Certificate serverCertificate, bool clientCertificateRequired)
            : base(stream, serverCertificate, clientCertificateRequired, false)
        {
            Initialize();
        }

        public SslServerStream(Stream stream, X509Certificate serverCertificate, bool clientCertificateRequired, bool ownsStream)
            : base(stream, serverCertificate, clientCertificateRequired, ownsStream)
        {
            Initialize();
        }

        private void Initialize()
        {
            PrivateKeyCertSelectionDelegate = new Tls.PrivateKeySelectionCallback(PrivateKeyCallback);
        }
    

        #endregion

        #region Methodes
        public void PrivateKeyFromFile(string filename)
        {
            if (!File.Exists(filename))
                throw new IOException("File " + filename + " not found");

            string content = File.ReadAllText(filename).Replace("\r","").Replace("\n","");
            
            int start, length;
            string privateKey;

            if (content.Contains("-----"))
            {
                if (content.Contains(beginToken))
                {
                    start = content.IndexOf(beginToken) + beginToken.Length;
                    length = content.IndexOf(endToken) - start;

                    privateKey = content.Substring(start, length);
                }
                else
                    throw new NotSupportedException("Only RSA is supported for key exchange");
            }
            else
                privateKey = content;
           

            Security.ASN1 asn1 = new Security.ASN1(Convert.FromBase64String(privateKey));


            PrivateKey = asn1[3].Value;            
        }


        public System.Security.Cryptography.AsymmetricAlgorithm PrivateKeyCallback(X509Certificate certificate, string targetHost)
        {

            string keyAlgo = certificate.GetKeyAlgorithm();
            RSAManaged rsa = new RSAManaged();

            System.Security.Cryptography.RSAParameters rsaParameters = new System.Security.Cryptography.RSAParameters();

            Security.ASN1 pubKey = new Security.ASN1(certificate.GetPublicKey());
            

            rsaParameters.Modulus = pubKey[0].Value;
            rsaParameters.Exponent = pubKey[1].Value;
            rsaParameters.D = this.privateKey;

            rsa.ImportParameters(rsaParameters);
            
            return rsa;
        }


        protected override void Dispose(bool disposing)
        {
            Array.Clear(privateKey, 0, privateKey.Length);
            privateKey = null;


            base.Dispose(disposing);
        }

       

        #endregion
         
    }
}
