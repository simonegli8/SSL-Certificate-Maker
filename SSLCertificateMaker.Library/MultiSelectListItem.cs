using Org.BouncyCastle.Asn1.X509;

namespace SSLCertificateMaker
{
	public class MultiSelectListItem<T>
	{
		public string Key { get; private set; }
		public T Value { get; private set; }
		public MultiSelectListItem()
		{
		}
		public MultiSelectListItem(string key, T value)
		{
			Key = key;
			Value = value;
		}
		public override string ToString()
		{
			return Key;
		}
	}
    public class MultiSelectKeyPurposeItem : MultiSelectListItem<KeyPurposeID> {
		public MultiSelectKeyPurposeItem(): base() { }
		public MultiSelectKeyPurposeItem(string key, KeyPurposeID value): base(key, value) { }
    }
    public class MultiSelectIntItem : MultiSelectListItem<int> {
		public MultiSelectIntItem(): base() { }
		public MultiSelectIntItem(string key, int value) : base(key, value) { }
	}
}
