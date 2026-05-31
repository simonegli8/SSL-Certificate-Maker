using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Crypt = System.Security.Cryptography;
using Ext=System.Security.Cryptography.X509Certificates.RSACertificateExtensions;
using Sys=System.Security.Cryptography.X509Certificates;

namespace SSLCertificateMaker.Library
{
    public class ReasonItem
    {
        public string Name { get; set; }
        public int Reason { get; set; }
		public ReasonItem(string name, int reason)
        {
            Name = name;
            Reason = reason;
        }
    }

    public static class CertMaker
	{
		internal static SecureRandom secureRandom = new SecureRandom();
        public static readonly ObservableCollection<ReasonItem> Reasons = new ObservableCollection<ReasonItem>(
			new[] { new ReasonItem("Unspecified", CrlReason.Unspecified),
             new ReasonItem("AACompromise", CrlReason.AACompromise),
             new ReasonItem("AffiliationChanged", CrlReason.AffiliationChanged),
             new ReasonItem("CACompromise", CrlReason.CACompromise),
             new ReasonItem("CertificateHold", CrlReason.CertificateHold),
             new ReasonItem("CessationOfOperation", CrlReason.CessationOfOperation),
             new ReasonItem("KeyCompromise", CrlReason.KeyCompromise),
             new ReasonItem("PrivilegeWithdrawn", CrlReason.PrivilegeWithdrawn),
             new ReasonItem("RemoveFromCrl", CrlReason.RemoveFromCrl),
             new ReasonItem("Superseded", CrlReason.Superseded),
		});

        public static int? ToInt(string name) => Reasons.FirstOrDefault(r => r.Name == name).Reason;
        public static string ToString(int? reason) => Reasons.FirstOrDefault(r => r.Reason == reason).Name;

		public static readonly string CaDirectory;
        public static readonly string CertDirectory;
        public static readonly string RevokedDirectory;
		static CertMaker()
		{
            //var exeDir = new DirectoryInfo(AppContext.BaseDirectory);
            var documentsDir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (string.IsNullOrEmpty(documentsDir))
            {
                documentsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents");
                if (!Directory.Exists(documentsDir)) Directory.CreateDirectory(documentsDir);
            }

            CertDirectory = Path.Combine(documentsDir, "SSL-Certificates");
            CaDirectory = Path.Combine(CertDirectory, "CertificateAuthority");
            RevokedDirectory = Path.Combine(CertDirectory, "RevokedCertificates");
            Directory.CreateDirectory(CaDirectory);
            Directory.CreateDirectory(CertDirectory);
        }
        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
		{
			KeyGenerationParameters keygenParam = new KeyGenerationParameters(secureRandom, length);

			RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
			keyGenerator.Init(keygenParam);
			return keyGenerator.GenerateKeyPair();
		}

		private static AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName)
		{
			X9ECParameters ecParam = SecNamedCurves.GetByName(curveName);
			ECDomainParameters ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
			ECKeyGenerationParameters keygenParam = new ECKeyGenerationParameters(ecDomain, secureRandom);

			ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
			keyGenerator.Init(keygenParam);
			return keyGenerator.GenerateKeyPair();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="domains"></param>
		/// <param name="subjectPublic"></param>
		/// <param name="issuerName"></param>
		/// <param name="issuerPublic"></param>
		/// <param name="issuerPrivate"></param>
		/// <returns></returns>
		private static X509Certificate GenerateCertificate(MakeCertArgs args, AsymmetricKeyParameter subjectPublic,
			string issuerName, AsymmetricKeyParameter issuerPublic, AsymmetricKeyParameter issuerPrivate,
			BigInteger issuerSerialNumber = null, X509Name issuerDN = null)
		{
			bool isCA = args.KeyUsage == (KeyUsage.CrlSign | KeyUsage.KeyCertSign);

			ISignatureFactory signatureFactory;
			if (issuerPrivate is ECPrivateKeyParameters)
			{
				signatureFactory = new Asn1SignatureFactory(
					X9ObjectIdentifiers.ECDsaWithSha256.Id,
					issuerPrivate);
			}
			else
			{
				signatureFactory = new Asn1SignatureFactory(
					PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id,
					issuerPrivate);
			}

			X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
			certGenerator.SetIssuerDN(new X509Name("CN=" + issuerName));
			certGenerator.SetSubjectDN(new X509Name("CN=" + args.Domains[0]));
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[16]; // 128-bit serial (good practice)
            random.NextBytes(bytes);
            BigInteger serial = new BigInteger(1, bytes);
            certGenerator.SetSerialNumber(serial);
			certGenerator.SetNotBefore(args.ValidFrom);
			certGenerator.SetNotAfter(args.ValidTo);
			certGenerator.SetPublicKey(subjectPublic);

			if (issuerPublic != null)
			{
                var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerPublic);
                var aki = new AuthorityKeyIdentifier(spki,
                    new GeneralNames(new GeneralName(issuerDN)),
					issuerSerialNumber);

				certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, aki);
			}

			// Subject Key Identifier
			SubjectKeyIdentifierStructure skis = new SubjectKeyIdentifierStructure(subjectPublic);
			certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, skis);

			if (!isCA || args.Domains.Length > 1)
			{
				// Add SANs (Subject Alternative Names)
				GeneralName[] names = args.Domains.Select(domain => new GeneralName(GetGeneralNameType(domain), domain)).ToArray();
				GeneralNames subjectAltName = new GeneralNames(names);
				certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
			}

			// Specify allowed key usage
			if (args.KeyUsage != 0)
				certGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(args.KeyUsage));
			if (args.ExtendedKeyUsage.Length != 0)
				certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(args.ExtendedKeyUsage));

			// Specify Basic Constraints
			certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCA));
          
			if (isCA && !string.IsNullOrWhiteSpace(args.CertificateRevocationListUrl))
            {
                var crlUri = new GeneralName(
                    GeneralName.UniformResourceIdentifier,
                    args.CertificateRevocationListUrl.Trim());

                var distPointName = new DistributionPointName(
                    new GeneralNames(crlUri));

                var distPoint = new DistributionPoint(
                    distPointName,
                    null,
                    null);

                var crlDistributionPoints = new CrlDistPoint(new[] { distPoint });

                certGenerator.AddExtension(
                    X509Extensions.CrlDistributionPoints,
                    false,
                    crlDistributionPoints);
            }

            if (isCA && !string.IsNullOrWhiteSpace(args.OCSPResponderUrl))
            {
                var aia = new AuthorityInformationAccess(
                    AccessDescription.IdADOcsp,
                    new GeneralName(
                        GeneralName.UniformResourceIdentifier,
                        args.OCSPResponderUrl.Trim()));

                certGenerator.AddExtension(
                    X509Extensions.AuthorityInfoAccess,
                    false,
                    aia);
            }
            return certGenerator.Generate(signatureFactory);
		}
		/// <summary>
		/// Returns <c>GeneralName.IPAddress</c> if the <c>domain</c> is an IPv4 or IPv6 address, otherwise returns <c>GeneralName.DnsName</c>.
		/// </summary>
		/// <param name="domain"></param>
		/// <returns></returns>
		private static int GetGeneralNameType(string domain)
		{
			if(IPAddress.TryParse(domain, out IPAddress ip))
			{
				if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
					return GeneralName.IPAddress;
				else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
					return GeneralName.IPAddress;
			}
			return GeneralName.DnsName;
		}

		private static bool ValidateCert(X509Certificate cert, ICipherParameters pubKey)
		{
			cert.CheckValidity(DateTime.UtcNow);
			var tbsCert = cert.GetTbsCertificate();
			var sig = cert.GetSignature();

			var signer = SignerUtilities.GetSigner(cert.SigAlgName);
			signer.Init(false, pubKey);
			signer.BlockUpdate(tbsCert, 0, tbsCert.Length);
			return signer.VerifySignature(sig);
		}
		private static bool IsSelfSigned(X509Certificate cert)
		{
			return ValidateCert(cert, cert.GetPublicKey());
		}

		//static IEnumerable<X509Certificate> BuildCertificateChain(X509Certificate primary, IEnumerable<X509Certificate> additional)
		//{
		//	PkixCertPathBuilder builder = new PkixCertPathBuilder();

		//	// Separate root from itermediate
		//	List<X509Certificate> intermediateCerts = new List<X509Certificate>();
		//	HashSet rootCerts = new HashSet();

		//	foreach (X509Certificate x509Cert in additional)
		//	{
		//		// Separate root and subordinate certificates
		//		if (IsSelfSigned(x509Cert))
		//			rootCerts.Add(new TrustAnchor(x509Cert, null));
		//		else
		//			intermediateCerts.Add(x509Cert);
		//	}

		//	// Create chain for this certificate
		//	X509CertStoreSelector holder = new X509CertStoreSelector();
		//	holder.Certificate = primary;

		//	// WITHOUT THIS LINE BUILDER CANNOT BEGIN BUILDING THE CHAIN
		//	intermediateCerts.Add(holder.Certificate);

		//	PkixBuilderParameters builderParams = new PkixBuilderParameters(rootCerts, holder);
		//	builderParams.IsRevocationEnabled = false;

		//	X509CollectionStoreParameters intermediateStoreParameters = new X509CollectionStoreParameters(intermediateCerts);

		//	builderParams.AddStore(X509StoreFactory.Create("Certificate/Collection", intermediateStoreParameters));

		//	PkixCertPathBuilderResult result = builder.Build(builderParams);

		//	return result.CertPath.Certificates.Cast<X509Certificate>();
		//}

		#region Public Methods
		/// <summary>
		/// Generates a self-signed certificate.
		/// </summary>
		/// <param name="domains">An array of domain names or "subject" common names / alternative names.  If making a certificate authority, you could just let this be a single string, not even a domain name but something like "Do Not Trust This Root CA".</param>
		/// <param name="keySizeBits">Key size in bits for the RSA keys.</param>
		/// <param name="validFrom">Start date for certificate validity.</param>
		/// <param name="validTo">End date for certificate validity.</param>
		/// <returns></returns>
		public static CertificateBundle GetCertificateSignedBySelf(MakeCertArgs args)
		{
			AsymmetricCipherKeyPair keys = GenerateRsaKeyPair(args.KeyStrength);
			X509Certificate cert = GenerateCertificate(args, keys.Public, args.Domains[0], null, keys.Private);

			return new CertificateBundle(cert, keys.Private);
		}

		/// <summary>
		/// Generates a certificate signed by the specified certificate authority.
		/// </summary>
		/// <param name="domains">An array of domain names or subject common names / alternative names.</param>
		/// <param name="keySizeBits">Key size in bits for the RSA keys.</param>
		/// <param name="validFrom">Start date for certificate validity.</param>
		/// <param name="validTo">End date for certificate validity.</param>
		/// <param name="ca">A CertificateBundle representing the CA used to sign the new certificate.</param>
		/// <returns></returns>
		public static CertificateBundle GetCertificateSignedByCA(MakeCertArgs args, CertificateBundle ca)
		{
			AsymmetricCipherKeyPair keys = GenerateRsaKeyPair(args.KeyStrength);
			X509Certificate cert = GenerateCertificate(args, keys.Public, ca.GetSubjectName(), ca.cert.GetPublicKey(),
				ca.privateKey, ca.cert.SerialNumber, ca.cert.SubjectDN);

			CertificateBundle b = new CertificateBundle(cert, keys.Private);
			b.SetIssuerBundle(ca);
			return b;
		}

        public static X509Crl GenerateCrl(
			X509Name subjectDN,
			DateTime lastUpdate,
			DateTime nextUpdate,
			AsymmetricKeyParameter caPrivateKey,
			IEnumerable<BigInteger> revokedSerials)
        {
            var crlGen = new X509V2CrlGenerator();

            // CRL issuer = CA subject
            crlGen.SetIssuerDN(subjectDN);

            // This update
            crlGen.SetThisUpdate(lastUpdate);

            // Next update
            crlGen.SetNextUpdate(nextUpdate);

            // Add revoked certificates
            foreach (var serial in revokedSerials)
            {
                crlGen.AddCrlEntry(
                    serial,
                    DateTime.UtcNow,
                    CrlReason.PrivilegeWithdrawn);
            }

            // Signature algorithm
            var signatureFactory = new Asn1SignatureFactory(
                "SHA256WITHRSA",
                caPrivateKey);

            return crlGen.Generate(signatureFactory);
        }

        public static X509Crl CreateCertificateRevocationList(string file, Sys.X509Certificate2 issuer, AsymmetricKeyParameter privateKey, DateTime lastUpdate, DateTime nextUpdate, RevokeItemsList items, CancellationToken cancel)
		{
#if NETCOREAPP
			if (privateKey == null)
			{
				var rsa = Ext.GetRSAPrivateKey(issuer);
				if (rsa == null)
					throw new InvalidOperationException("Issuer certificate has no RSA private key.");
				privateKey = DotNetUtilities.GetRsaKeyPair(rsa).Private;
			}
			var crl = GenerateCrl(new X509Name(issuer.Subject), lastUpdate, nextUpdate, privateKey, items.Select(item => new Org.BouncyCastle.Math.BigInteger(1, item.SerialNumber.ToByteArray())));
			return crl;
#else
			throw new PlatformNotSupportedException("NET Standard not supported.");
#endif
		}
        ///// <summary>
        ///// Generates a certificate signed by the specified certificate authority.
        ///// </summary>
        ///// <param name="domains">An array of domain names or subject common names / alternative names.</param>
        ///// <param name="keySizeBits">Key size in bits for the RSA keys.</param>
        ///// <param name="validFrom">Start date for certificate validity.</param>
        ///// <param name="validTo">End date for certificate validity.</param>
        ///// <param name="caName">The name of the certificate authority, e.g. "Do Not Trust This Root CA".</param>
        ///// <param name="caPublic">The public key of the certificate authority.  May be null if you don't have it handy.</param>
        ///// <param name="caPrivate">The private key of the certificate authority.</param>
        ///// <returns></returns>
        //public static CertificateBundle GetCertificateSignedByCA(string[] domains, int keySizeBits, DateTime validFrom, DateTime validTo, string caName, AsymmetricKeyParameter caPublic, AsymmetricKeyParameter caPrivate)
        //{
        //	AsymmetricCipherKeyPair keys = GenerateRsaKeyPair(keySizeBits);
        //	X509Certificate cert = GenerateCertificate(domains, keys.Public, validFrom, validTo, caName, caPublic, caPrivate, null);

        //	return new CertificateBundle(cert, keys.Private);
        //}
        #endregion
    }

	public class CertificateBundle
	{
		public X509Certificate cert;
		public AsymmetricKeyParameter privateKey;
		public X509Certificate[] chain = new X509Certificate[0];
		public CertificateBundle() { }
		public CertificateBundle(X509Certificate cert, AsymmetricKeyParameter privateKey)
		{
			this.cert = cert;
			this.privateKey = privateKey;
		}
		public string GetSubjectName()
		{
			return GetSubjectName(cert);
		}
		private static string GetSubjectName(X509Certificate cert)
		{
			if (cert == null)
				return "Unknown";
			string subject = cert.SubjectDN.ToString();
			if (subject.StartsWith("cn=", StringComparison.OrdinalIgnoreCase))
				subject = subject.Substring(3);
			return subject;
		}
		/// <summary>
		/// Gets the certificate and chain concatenated into a single .pem file (DER → Base64 → ASCII).  Each certificate is the issuer of the certificate before it.
		/// </summary>
		/// <returns></returns>
		public byte[] GetPublicCertAsCerFile()
		{
			using (TextWriter textWriter = new StringWriter())
			{
				PemWriter pemWriter = new PemWriter(textWriter);
				pemWriter.WriteObject(cert);
				foreach (X509Certificate link in chain)
					pemWriter.WriteObject(link);
				pemWriter.Writer.Flush();
				string strKey = textWriter.ToString();
				return Encoding.ASCII.GetBytes(strKey);
			}
		}
		/// <summary>
		/// Gets the private key as a .pem file (DER → Base64 → ASCII).
		/// </summary>
		/// <returns></returns>
		public byte[] GetPrivateKeyAsKeyFile()
		{
			using (TextWriter textWriter = new StringWriter())
			{
				PemWriter pemWriter = new PemWriter(textWriter);
				pemWriter.WriteObject(privateKey);
				pemWriter.Writer.Flush();
				string strKey = textWriter.ToString();
				return Encoding.ASCII.GetBytes(strKey);
			}
		}
		/// <summary>
		/// Exports the certificate as a pfx file, optionally including the private key.
		/// </summary>
		/// <param name="password">If non-null, a password is required to use the resulting pfx file.</param>
		/// <returns></returns>
		public byte[] GetPfx(string password)
		{
			string subject = GetSubjectName();
			Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder()
                .SetUseDerEncoding(true)
                .Build();
			X509CertificateEntry certEntry = new X509CertificateEntry(cert);
			X509CertificateEntry[] chainEntries = new X509CertificateEntry[] { certEntry }.Concat(chain.Select(c => new X509CertificateEntry(c))).ToArray();
			foreach (X509CertificateEntry ce in chainEntries)
				pkcs12Store.SetCertificateEntry(GetSubjectName(ce.Certificate), ce);
			pkcs12Store.SetKeyEntry(subject, new AsymmetricKeyEntry(privateKey), chainEntries);
			using (MemoryStream pfxStream = new MemoryStream())
			{
				pkcs12Store.Save(pfxStream, password == null ? null : password.ToCharArray(), CertMaker.secureRandom);
				var pfxBCBytes = pfxStream.ToArray();
#if NETSTANDARD2_0
				return pfxBCBytes;
#else
				var cert2 = Sys.X509CertificateLoader.LoadPkcs12(pfxBCBytes, password,
					Sys.X509KeyStorageFlags.Exportable | Sys.X509KeyStorageFlags.EphemeralKeySet);
                byte[] pfxBytes = cert2.Export(Sys.X509ContentType.Pfx, password);
				return pfxBytes;
#endif
            }
		}
		/// <summary>
		/// Loads a CertificateBundle from .cer and .key files.
		/// </summary>
		/// <param name="publicCer">The path to the public .cer file.  If null or the file does not exist, the resulting CertificateBundle will have a null [cert] field.</param>
		/// <param name="privateKey">The path to the private .key file.  If null or the file does not exist, the resulting CertificateBundle will have a null [privateKey] field.</param>
		/// <returns></returns>
		public static CertificateBundle LoadFromCerAndKeyFiles(string publicCer, string privateKey)
		{
			string[] pemFilePaths = new string[] { publicCer, privateKey };
			List<AsymmetricKeyParameter> keys = new List<AsymmetricKeyParameter>();
			List<X509Certificate> certs = new List<X509Certificate>();
			StringBuilder sbDebugWhatWasFound = new StringBuilder();
			foreach (string path in pemFilePaths)
			{
				if (path != null && File.Exists(path))
				{
					using (StreamReader sr = new StreamReader(path, Encoding.ASCII))
					{
						PemReader reader = new PemReader(sr);
						object obj = reader.ReadObject();
						while (obj != null)
						{
							sbDebugWhatWasFound.AppendLine(path + ": " + obj.GetType().ToString());

							if (obj is AsymmetricCipherKeyPair)
								keys.Add(((AsymmetricCipherKeyPair)obj).Private);
							else if (obj is AsymmetricKeyParameter)
								keys.Add((AsymmetricKeyParameter)obj);
							else if (obj is X509Certificate)
								certs.Add((X509Certificate)obj);

							obj = reader.ReadObject();
						}
					}
				}
			}
			if (keys.Count == 0)
				throw new ApplicationException("Private key was not found in input files \"" + string.Join("\", \"", pemFilePaths) + "\"." + Environment.NewLine
				+ "For debugging purposes, here is what was found:" + Environment.NewLine + sbDebugWhatWasFound.ToString());
			else if (keys.Count > 1)
				throw new ApplicationException(keys.Count + " private keys were found in input files \"" + string.Join("\", \"", pemFilePaths) + "\" (this program doesn't know which key to use)." + Environment.NewLine
				+ "For debugging purposes, here is what was found:" + Environment.NewLine + sbDebugWhatWasFound.ToString());

			X509Certificate primary = certs.FirstOrDefault(c => DoesCertificateMatchKey(c, keys[0]));
			if (primary == null)
				throw new ApplicationException("The public key matching the private key was not found in input files \"" + string.Join("\", \"", pemFilePaths) + "\"." + Environment.NewLine
				+ "For debugging purposes, here is what was found:" + Environment.NewLine + sbDebugWhatWasFound.ToString());

			X509Certificate[] fullchain = ChainBuilder.BuildChain(primary, certs.Where(c => c != primary));

			CertificateBundle b = new CertificateBundle();
			b.cert = fullchain[0];
			b.chain = fullchain.Skip(1).ToArray();
			b.privateKey = keys[0];
			return b;
		}

		/// <summary>
		/// Loads a CertificateBundle from a .pfx file.
		/// </summary>
		/// <param name="filePath">The path to the .pfx file.</param>
		/// <param name="password">The password required to access the .pfx file, or null.</param>
		/// <returns></returns>
		public static CertificateBundle LoadFromPfxFile(string filePath, string password)
		{
			try
			{
				using (Stream fileStream = File.OpenRead(filePath))
				{
					Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder().Build();
					pkcs12Store.Load(fileStream, password == null ? null : password.ToCharArray());
					foreach (string alias in pkcs12Store.Aliases)
					{
						CertificateBundle b = new CertificateBundle();
						X509CertificateEntry[] entryChain = pkcs12Store.GetCertificateChain(alias);
						if (entryChain == null)
							continue;
						X509Certificate[] pfxChain = entryChain.Select(e => e.Certificate).ToArray();
						b.cert = pfxChain.First();
						b.privateKey = pkcs12Store.GetKey(alias)?.Key;
						X509Certificate[] fullchain = ChainBuilder.BuildChain(b.cert, pfxChain.Skip(1));
						b.chain = fullchain.Skip(1).ToArray();
						if (b.cert != null && b.privateKey != null)
							return b;
					}
					return null;
				}
			}
			catch (IOException)
			{
				return null;
			}
		}
		/// <summary>
		/// Returns true of the certificate has the public key that matches the private key. Supports RSA, DSA, and EC keys.
		/// </summary>
		/// <param name="cert">Certificate with a public key</param>
		/// <param name="privKey">Private key</param>
		/// <returns></returns>
		private static bool DoesCertificateMatchKey(X509Certificate cert, AsymmetricKeyParameter privKey)
		{
			AsymmetricKeyParameter pubKey = cert.GetPublicKey();
			if (pubKey is RsaKeyParameters && privKey is RsaPrivateCrtKeyParameters)
			{
				RsaKeyParameters a = (RsaKeyParameters)pubKey;
				RsaPrivateCrtKeyParameters b = (RsaPrivateCrtKeyParameters)privKey;
				return a.Exponent.Equals(b.PublicExponent) && a.Modulus.Equals(b.Modulus);
			}
			else if (pubKey is DsaPublicKeyParameters && privKey is DsaPrivateKeyParameters)
			{
				DsaPublicKeyParameters a = (DsaPublicKeyParameters)pubKey;
				DsaPrivateKeyParameters b = (DsaPrivateKeyParameters)privKey;
				return a.Y.Equals(b.Parameters.G.ModPow(b.X, b.Parameters.P));
			}
			else if (pubKey is ECPublicKeyParameters && privKey is ECPrivateKeyParameters)
			{
				ECPublicKeyParameters a = (ECPublicKeyParameters)pubKey;
				ECPrivateKeyParameters b = (ECPrivateKeyParameters)privKey;
				return a.Q.Equals(b.Parameters.G.Multiply(b.D));
			}
			return false;
		}
		/// <summary>
		/// Sets the <see cref="chain"/> field to the issuer's certificate and chain.
		/// </summary>
		/// <param name="issuerBundle"></param>
		public void SetIssuerBundle(CertificateBundle issuerBundle)
		{
			chain = new X509Certificate[] { issuerBundle.cert }.Concat(issuerBundle.chain).ToArray();
		}
	}
}