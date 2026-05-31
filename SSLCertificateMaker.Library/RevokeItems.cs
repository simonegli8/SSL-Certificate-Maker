using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Numerics;
using System.Data;

namespace SSLCertificateMaker.Library
{

    public sealed class BigIntegerStringConverter : JsonConverter<BigInteger>
    {
        public override BigInteger Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            return reader.TokenType switch
            {
                JsonTokenType.String =>
                    BigInteger.Parse(reader.GetString()!, System.Globalization.NumberStyles.HexNumber),

                JsonTokenType.Number =>
                    BigInteger.Parse(reader.GetDecimal().ToString(), System.Globalization.NumberStyles.HexNumber),

                _ => throw new JsonException()
            };
        }

        public override void Write(
            Utf8JsonWriter writer,
            BigInteger value,
            JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString("X"));
        }
    }

    public class RevokeItem
    {
        [DefaultValue(null)]
        public string File { get; set; } = string.Empty;
        [JsonIgnore]
        public string Name => Path.GetFileNameWithoutExtension(File);
        [JsonPropertyName("Reason")]
        public string ReasonName { get => CertMaker.ToString(Reason); set => Reason = CertMaker.ToInt(value); }
        [JsonIgnore]
        public int? Reason { get; set; }

        public System.Numerics.BigInteger SerialNumber { get; set; }
    }

    public class RevokeItemsList : KeyedCollection<System.Numerics.BigInteger, RevokeItem>
    {
        protected override System.Numerics.BigInteger GetKeyForItem(RevokeItem item) => item.SerialNumber;
        public ObservableCollection<RevokeItem> Observable = new ObservableCollection<RevokeItem>();
        public string ConfigFile => Path.Combine(CertMaker.RevokedDirectory, "RevokedCertificates.json");
        protected override void InsertItem(int index, RevokeItem item)
        {
            base.InsertItem(index, item);
            Observable.Insert(index, item);
        }
        protected override void RemoveItem(int index)
        {
            base.RemoveItem(index);
            Observable.RemoveAt(index);
        }
        protected override void SetItem(int index, RevokeItem item)
        {
            base.SetItem(index, item);
            Observable[index] = item;
        }
        public new void Add(RevokeItem item)
        {
            if (Contains(item.SerialNumber)) Remove(item.SerialNumber);
            base.Add(item);
        }
        public new void Remove(BigInteger serialNumber)
        {
            if (Contains(serialNumber))
            {
                var item = this[serialNumber];
                var index = IndexOf(item);
                RemoveItem(index);
            }
        }
        public new void Clear()
        {
            base.Clear();
            Observable.Clear();
        }
        public RevokeItemsList Save()
        {
            Directory.CreateDirectory(CertMaker.RevokedDirectory);
            var options = new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter(), new BigIntegerStringConverter() },
                WriteIndented = true,
                IndentCharacter = '\t',
                IndentSize = 1
            };
            var json = JsonSerializer.Serialize(this.ToArray(), options);
            File.WriteAllText(ConfigFile, json);

            return this;
        }
        public RevokeItemsList Load()
        {
            Directory.CreateDirectory(CertMaker.RevokedDirectory);
            if (File.Exists(ConfigFile))
            {
                var text = File.ReadAllText(ConfigFile);
                if (!string.IsNullOrWhiteSpace(text))
                {
                    var options = new JsonSerializerOptions
                    {
                        Converters = { new JsonStringEnumConverter(), new BigIntegerStringConverter() }
                    };
                    var items = JsonSerializer.Deserialize<RevokeItem[]>(text, options);
                    Clear();
                    foreach (var item in items) Add(item);
                    return this;
                }
            }
            Clear();
            return this;
        }
    }
}
