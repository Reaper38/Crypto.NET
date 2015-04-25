// X509CertificateBuilder.cs - An easy to use class for building self signed X509 certificates

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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using M = CryptoNet.Security.X509;

namespace CryptoNet
{
    public class X509CertificateBuilder
    {
        //E=test@asdasd.com, CN=MyName, OU=UnitNName, O=TestFirma, L=Doetlingen, S=Niedersachsen, C=DE

        private M.X509CertificateBuilder builder;
        

        private string countryCode, state, city, organizationName, organizationalUnitName, commonName, email;
        private DateTime notBefore = DateTime.Now;
        private DateTime notAfter = DateTime.Now.AddDays(365);
        private byte[] serialNumber = new byte[] {1};
        private X509Certificate signerCert;
        

        /// <summary>
        /// 2 letter code of the country
        /// </summary>
        public string CountryCode
        {
            get { return (countryCode == null) ? "" : countryCode; }
            set { countryCode = value;  }
        }

        /// <summary>
        /// State or Province Name (full name) 
        /// </summary>
        public string State
        {
            get { return (state == null) ? "" : state; }
            set { state = value;  }
        }

        /// <summary>
        /// Locality Name (eg, city)
        /// </summary>
        public string City
        {
            get { return (city == null) ? "" : city; }
            set { city = value; }
        }

        /// <summary>
        /// Organization Name (eg, company)
        /// </summary>
        public string OrganizationName
        {
            get { return (organizationName == null) ? "" : organizationName; }
            set { organizationName = value; }
        }

        /// <summary>
        /// Organizational Unit Name (eg, section)
        /// </summary>
        public string OrganizationalUnitName
        {
            get { return (organizationalUnitName == null) ? "" : organizationalUnitName; }
            set { organizationalUnitName = value;  }
        }

        /// <summary>
        /// Common Name (eg, YOUR name)
        /// </summary>
        public string CommonName
        {
            get { return (commonName == null) ? "" : commonName; }
            set { commonName = value; }
        }

        /// <summary>
        /// Email Address
        /// </summary>
        public string Email
        {
            get { return (email == null) ? "" : email; }
            set { email = value; }
        }


        /// <summary>
        /// Don't use this certificate before...
        /// </summary>
        public DateTime NotBefore
        {
            get { return notBefore; }
            set { notBefore = value; }
        }

        /// <summary>
        /// Don't use this certificate after...
        /// </summary>
        public DateTime NotAfter
        {
            get { return notAfter; }
            set { NotAfter = value; }
        }


        /// <summary>
        /// Serialnumber of the certificate
        /// </summary>
        public byte[] SerialNumber
        {
            get { return serialNumber; }
            set { serialNumber = value; }
        }

        /// <summary>
        /// The certificate for the signation. 
        /// Let the value be null for a self-signed certificate
        /// </summary>
        public X509Certificate SignerCertificate
        {
            get { return signerCert; }
            set { signerCert = value; }
        }

   

        public X509Certificate Build(AsymmetricAlgorithm publicKey)
        {
            byte[] certificate;

            builder = new M.X509CertificateBuilder();
            //E=test@asdasd.com, CN=MyName, OU=UnitNName, O=TestFirma, L=Doetlingen, S=Niedersachsen, C=DE

            builder.SubjectName = String.Format("E={0}, CN={1}, OU={2}, O={3}, L={4}, S={5}, C={6}", Email, CommonName, OrganizationalUnitName, OrganizationName, City, State, CountryCode);

            if (NotBefore == null || NotAfter == null || NotAfter <= NotBefore)
                throw new Exception("Error in NotBefore or NotAfter date");

            builder.NotBefore = NotBefore;
            builder.NotAfter = NotAfter;
            builder.SerialNumber = SerialNumber;
            builder.Version = 3;


            if (publicKey == null)
                throw new Exception("publicKey was null");
            builder.SubjectPublicKey = publicKey;

            //Self-signed cert.
            if (signerCert == null)
            {
                builder.IssuerName = String.Format("E={0}, CN={1}, OU={2}, O={3}, L={4}, S={5}, C={6}", Email, CommonName, OrganizationalUnitName, OrganizationName, City, State, CountryCode);
                certificate = builder.Sign(publicKey);
            }
            else
            {
                builder.IssuerName = signerCert.Subject;
                AsymmetricAlgorithm signKey;

                if (signerCert.GetKeyAlgorithm().StartsWith("RSA"))
                {
                    signKey = RSAManaged.Create();
                    RSAParameters rsaParams = new RSAParameters();
                    rsaParams.Modulus = signerCert.GetPublicKey();
                    ((RSAManaged)signKey).ImportParameters(rsaParams);
                }
                //TO-DO: other key algorithms
                else
                    throw new Exception("The key algorithmen " + signerCert.GetKeyAlgorithm() + " isn't supported yet");


                certificate = builder.Sign(signKey);
            }



            return new X509Certificate(certificate);

           
        }



     


    }
}
