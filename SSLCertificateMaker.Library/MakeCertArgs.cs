using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using System;

namespace SSLCertificateMaker
{
	public class MakeCertArgs
	{
		public int KeyStrength;
		public DateTime ValidFrom;
		public DateTime ValidTo;
		public string[] Domains;
		public string Password;
		public bool SaveCerAndKey;
		public string Issuer;
		public string OutputPath;
		public int KeyUsage;
		public KeyPurposeID[] ExtendedKeyUsage;
		public string CertificateRevocationListUrl;
		public string OCSPResponderUrl;


        public MakeCertArgs(int keyStrength, DateTime validFrom, DateTime validTo, string[] domains, string password, bool saveCerAndKey, string issuerCert, int KeyUsage, KeyPurposeID[] ExtendedKeyUsage,
			string certificateRevocationList, string ocspResponderUrl)
		{
			this.KeyStrength = keyStrength;
			this.ValidFrom = validFrom;
			this.ValidTo = validTo;
			this.Domains = domains;
			this.Password = password;
			this.SaveCerAndKey = saveCerAndKey;
			this.Issuer = issuerCert;
			this.KeyUsage = KeyUsage;
			this.ExtendedKeyUsage = ExtendedKeyUsage;
			this.CertificateRevocationListUrl = certificateRevocationList;
			this.OCSPResponderUrl = ocspResponderUrl;
		}
	}
}
