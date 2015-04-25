// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez

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
using System.Collections.Generic;
using System.Text;
using System.IO;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace CryptoSharp.SSL
{
	#region Delegates

	public delegate bool CertificateValidationCallback(
		X509Certificate certificate, 
		int[]			certificateErrors);

	public delegate X509Certificate CertificateSelectionCallback(
		X509CertificateCollection	clientCertificates, 
		X509Certificate				serverCertificate, 
		string						targetHost, 
		X509CertificateCollection	serverRequestedCertificates);

	public delegate AsymmetricAlgorithm PrivateKeySelectionCallback(
		X509Certificate	certificate, 
		string			targetHost);

	#endregion

	public class SslClientStream : Tls.SslClientStream
	{
	

		#region Constructors
		
		public SslClientStream(
			Stream	stream, 
			string	targetHost, 
			bool	ownsStream) 
			: this(
				stream, targetHost, ownsStream,
                Tls.SecurityProtocolType.Default, null)
		{
		}
		
		public SslClientStream(
			Stream				stream, 
			string				targetHost, 
			X509Certificate		clientCertificate) 
			: this(
                stream, targetHost, false, Tls.SecurityProtocolType.Default, 
				new X509CertificateCollection(new X509Certificate[]{clientCertificate}))
		{
		}

		public SslClientStream(
			Stream						stream,
			string						targetHost, 
			X509CertificateCollection clientCertificates) : 
			this(
                stream, targetHost, false, Tls.SecurityProtocolType.Default, 
				clientCertificates)
		{
		}

		public SslClientStream(
			Stream					stream,
			string					targetHost,
			bool					ownsStream,
            Tls.SecurityProtocolType securityProtocolType) 
			: this(
				stream, targetHost, ownsStream, securityProtocolType,
				new X509CertificateCollection())
		{
		}

		public SslClientStream(
			Stream						stream,
			string						targetHost,
			bool						ownsStream,
            Tls.SecurityProtocolType securityProtocolType,
			X509CertificateCollection	clientCertificates):
			base(stream, targetHost, ownsStream, securityProtocolType, clientCertificates)
		{
		}

		#endregion

	
	}
}
