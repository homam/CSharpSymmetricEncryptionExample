using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;
using System.Diagnostics;
using System.IO.Compression;

namespace MLearning
{
    public static class Utilities
    {
        public static T Cast<G, T>(this G obj) where T : G
        {
            return (T)obj;
        }

        #region Copy
        /// <summary>
        /// Fast, but throws exception if <paramref name="obj"/> does not have all properties of <paramref name="data"/>.
        /// </summary>
        /// <typeparam name="TypeToCopyFrom"></typeparam>
        /// <typeparam name="TypeToCopyTo"></typeparam>
        /// <param name="data"></param>
        /// <param name="obj"></param>
        public static void Copy<TypeToCopyFrom, TypeToCopyTo>(TypeToCopyFrom data, ref TypeToCopyTo obj) where TypeToCopyTo : TypeToCopyFrom
        {
            if (data != null)
            {
                var props = typeof(TypeToCopyFrom).GetProperties();
                foreach (var prop in props)
                {
                    prop.SetValue(obj, prop.GetValue(data, null), null);
                }
            }
        }
        /// <summary>
        /// Works like <see cref="Copy"/> but it ensures that
        /// <list type="">
        /// <item>the destination has a property with the same name, if not it just continues through other properties</item>
        /// <item>the type of properties in both source and destination are the same</item></list>
        /// <para>It uses Equal method to find out if the value of properties are different.</para>
        /// </summary>
        /// <typeparam name="TypeToCopyFrom"></typeparam>
        /// <typeparam name="TypeToCopyTo"></typeparam>
        /// <param name="data"></param>
        /// <param name="obj"></param>
        public static void CopySimilarType<TypeToCopyFrom, TypeToCopyTo>(TypeToCopyFrom data, ref TypeToCopyTo obj)
        {
            if (data != null)
            {
                var sprops = typeof(TypeToCopyFrom).GetProperties();
                var dprops = typeof(TypeToCopyTo).GetProperties();

                foreach (var srpop in sprops)
                {
                    var dprop = dprops.SingleOrDefault(dp => dp.Name == srpop.Name);
                    if ((dprop != null) && (dprop.PropertyType.Equals(srpop.PropertyType)))
                    {
                        if (dprop.CanWrite)
                            dprop.SetValue(obj, srpop.GetValue(data, null), null);
                    }
                }
            }
        }

        /// <summary>
        /// The safest Copy method.
        /// <para>It uses Equal method to find out if the value of properties are different.</para>
        /// </summary>
        /// <typeparam name="TypeToCopyFrom"></typeparam>
        /// <typeparam name="TypeToCopyTo"></typeparam>
        /// <param name="data"></param>
        /// <param name="obj"></param>
        public static void CopySimilarTypeIfChanged<TypeToCopyFrom, TypeToCopyTo>(TypeToCopyFrom data, ref TypeToCopyTo obj)
        {
            if (data != null)
            {
                var sprops = typeof(TypeToCopyFrom).GetProperties();
                var dprops = typeof(TypeToCopyTo).GetProperties();

                foreach (var srpop in sprops)
                {
                    var dprop = dprops.SingleOrDefault(dp => dp.Name == srpop.Name);
                    if ((dprop != null) && (dprop.PropertyType.Equals(srpop.PropertyType)))
                    {
                        var dataValue = srpop.GetValue(data, null);
                        var objValue = dprop.GetValue(obj, null);
                        if (dataValue != null && !dataValue.Equals(objValue))
                            dprop.SetValue(obj, srpop.GetValue(data, null), null);
                    }
                }
            }
        }

        /// <summary>
        /// Fast, but throws exception if <paramref name="obj"/> does not have all properties of <paramref name="data"/>.
        /// </summary>
        /// <typeparam name="TypeToCopyFrom"></typeparam>
        /// <typeparam name="TypeToCopyTo"></typeparam>
        /// <param name="data"></param>
        /// <param name="obj"></param>
        public static void CopyIfChanged<TypeToCopyFrom, TypeToCopyTo>(TypeToCopyFrom data, ref TypeToCopyTo obj) where TypeToCopyTo : TypeToCopyFrom
        {
            var props = typeof(TypeToCopyFrom).GetProperties();
            foreach (var prop in props)
            {
                var dataValue = prop.GetValue(data, null);
                var objValue = prop.GetValue(obj, null);
                if (dataValue != null && !dataValue.Equals(objValue))
                    prop.SetValue(obj, dataValue, null);
            }
        }
        #endregion

        #region MD5

        public static string Md5Hash(this string input)
        {
            // Create a new instance of the MD5CryptoServiceProvider object.
            MD5 md5Hasher = MD5.Create();

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hasher.ComputeHash(Encoding.Default.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        public static bool Md5Hash(string input, string hash)
        {
            // Hash the input.
            string hashOfInput = Md5Hash(input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion

        #region GZip

        public static byte[] GZip(byte[] file, System.IO.Compression.CompressionMode compressionMode)
        {
            if (compressionMode == System.IO.Compression.CompressionMode.Compress)
            {
                using (MemoryStream inFile = new MemoryStream(file))
                {
                    // Create the compressed file.
                    using (MemoryStream outFile = new MemoryStream())
                    {
                        using (GZipStream gzip = new GZipStream(outFile,
                                CompressionMode.Compress))
                        {
                            // Copy the source file into the compression stream.
                            byte[] buffer = new byte[4096];
                            int numRead;
                            while ((numRead = inFile.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                gzip.Write(buffer, 0, numRead);
                            }
                        }
                        return outFile.ToArray();
                    }
                }
            }
            else
            {
                using (MemoryStream inFile = new MemoryStream(file))
                {
                    //Create the decompressed file.
                    using (MemoryStream outFile = new MemoryStream())
                    {
                        using (GZipStream gzip = new GZipStream(inFile,
                                CompressionMode.Decompress))
                        {
                            //Copy the decompression stream into the output file.
                            byte[] buffer = new byte[4096];
                            int numRead;
                            while ((numRead = gzip.Read(buffer, 0, buffer.Length)) != 0)
                            {
                                outFile.Write(buffer, 0, numRead);
                            }

                            outFile.Seek(0, 0);
                            return outFile.ToArray();
                        }
                    }
                }
            }
        }

        #endregion

        public const string SUBDOMAIN_REGEX = @"[a-zA-Z]{1,1}[a-zA-Z0-9\-]{3,20}";

        public static bool IsValidSubdomain(string subdomain)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(subdomain, SUBDOMAIN_REGEX);
        }

        #region Serialize/Deserialize

        public static string SerializeToXml<T>(this T o)
        {
            string xml = null;
            var xmlSerializer = new XmlSerializer(o.GetType());
            {
                using (var memoryStream = new MemoryStream())
                {
                    xmlSerializer.Serialize(memoryStream, o);
                    memoryStream.Seek(0, 0);
                    using (var streamReader = new StreamReader(memoryStream))
                    {
                        xml = streamReader.ReadToEnd();
                    }
                }
            }
            return xml;
        }

        public static string SerializeToXml<T>(this T o, Type t)
        {
            string xml = null;
            var xmlSerializer = new XmlSerializer(t);
            {
                using (var memoryStream = new MemoryStream())
                {
                    xmlSerializer.Serialize(memoryStream, o);
                    memoryStream.Seek(0, 0);
                    using (var streamReader = new StreamReader(memoryStream))
                    {
                        xml = streamReader.ReadToEnd();
                    }
                }
            }
            return xml;
        }


        public static string SerializeToXml(this Object o)
        {
            string xml = null;
            var xmlSerializer = new XmlSerializer(o.GetType());
            {
                using (var memoryStream = new MemoryStream())
                {
                    xmlSerializer.Serialize(memoryStream, o);
                    memoryStream.Seek(0, 0);
                    using (var streamReader = new StreamReader(memoryStream))
                    {
                        xml = streamReader.ReadToEnd();
                    }
                }
            }
            return xml;
        }

        public static string SerializeToXml(this Object o, bool useDataContractSerialization)
        {
            if (!useDataContractSerialization) return SerializeToXml(o);

            string xml;
            var serializer = new System.Runtime.Serialization.DataContractSerializer(o.GetType());
            {
                using (var memoryStream = new MemoryStream())
                {
                    serializer.WriteObject(memoryStream, o);
                    memoryStream.Seek(0, 0);
                    using (var streamReader = new StreamReader(memoryStream))
                    {
                        xml = streamReader.ReadToEnd();
                    }
                }
            }
            return xml;
        }

        public static T DeserailizeFromXml<T>(this string xml)
        {
            T o = default(T);
            var xmlSerializer = new XmlSerializer(typeof(T));
            {
                var textReader = new StringReader(xml);
                o = (T)xmlSerializer.Deserialize(textReader);
            }
            return o;
        }

        public static T DeserailizeFromXml<T>(this string xml, Type type)
        {
            T o = default(T);
            var xmlSerializer = new XmlSerializer(type);
            {
                var textReader = new StringReader(xml);
                o = (T)xmlSerializer.Deserialize(textReader);
            }
            return o;
        }

        /// <summary>
        /// Not tested
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="xml"></param>
        /// <param name="useDataContractSerializer"></param>
        /// <returns></returns>
        public static T DeserailizeFromXml<T>(this string xml, bool useDataContractSerializer)
        {
            T o = default(T);
            var xmlSerializer = new System.Runtime.Serialization.DataContractSerializer(typeof(T));
            {
                using (var ms = new MemoryStream())
                {
                    var textWriter = new StreamWriter(ms);
                    textWriter.Write(xml);
                    textWriter.Flush();
                    ms.Seek(0, 0);
                    o = (T)xmlSerializer.ReadObject(ms);
                }
            }
            return o;
        }

        public static Byte[] SerializeToByteArray(this Object o)
        {
            Byte[] bytes = null;
            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (var memoryStream = new MemoryStream())
            {
                bf.Serialize(memoryStream, o);
                bytes = memoryStream.ToArray();
            }
            return bytes;
        }

        public static T DeserializeFromByteArray<T>(this Byte[] bytes)
        {
            T o = default(T);
            var bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (var memoryStream = new MemoryStream(bytes))
            {
                o = (T)bf.Deserialize(memoryStream);
            }
            return o;
        }

        public static string SerializeByteArrayToString(this IEnumerable<Byte> buffer)
        {
            return Convert.ToBase64String(buffer is Byte[] ? (Byte[])buffer : buffer.ToArray());

            //            return Convert.ToBase64String(buffer.ToArray());
        }

        public static string SerializeByteArrayToHexString(this IEnumerable<Byte> buffer)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var s in buffer)
            {
                sb.Append(s.ToString("x", System.Globalization.CultureInfo.InvariantCulture));
                sb.Append(" ");
            }
            return sb.ToString().Trim();
        }

        public static Byte[] DeserializeHexStringToByteArray(this string value)
        {
            var arr = value.Split(' ');
            List<Byte> bytes = new List<byte>();
            foreach (var s in arr)
            {
                bytes.Add(byte.Parse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture));
            }
            return bytes.ToArray();
        }

        public static Byte[] DeserializeStringToByteArray(this string value)
        {
            return Convert.FromBase64String(value);
        }

        public static Byte[] DeserializeStringToByteArray(this IEnumerable<Char> chars)
        {
            var charArray = chars.ToArray();
            return Convert.FromBase64CharArray(charArray, 0, charArray.Length);
        }

        public static String SerializeJSON(this Object obj)
        {
            var json = new System.Web.Script.Serialization.JavaScriptSerializer();
            return json.Serialize(obj);
        }

        public static String SerializeJSON(this Object obj, bool useDataContractSerialization)
        {
            if (!useDataContractSerialization)
                return SerializeJSON(obj);

            System.Runtime.Serialization.Json.DataContractJsonSerializer ser = new System.Runtime.Serialization.Json.DataContractJsonSerializer(obj.GetType());
            using (MemoryStream ms = new MemoryStream())
            {
                ser.WriteObject(ms, obj);
                string json = Encoding.Default.GetString(ms.ToArray());
                return json;
            }
        }

        public static T DeserializeJSON<T>(this string value)
        {
            var json = new System.Web.Script.Serialization.JavaScriptSerializer();
            return json.Deserialize<T>(value);
        }

        public static Dictionary<String, T> DeserializeJSONDictionary<T>(this string value)
        {
            if (String.IsNullOrEmpty(value))
                return new Dictionary<String, T>();
            var json = new System.Web.Script.Serialization.JavaScriptSerializer();
            return json.Deserialize<Dictionary<String, T>>(value);
        }

        public static T DeserializeJSON<T>(this string value, bool useDataContractSerialization)
        {
            if (!useDataContractSerialization)
                return DeserializeJSON<T>(value);

            using (MemoryStream ms = new MemoryStream(Encoding.Unicode.GetBytes(value)))
            {
                System.Runtime.Serialization.Json.DataContractJsonSerializer ser = new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(T));
                T obj = (T)ser.ReadObject(ms);
                ms.Close();
                return obj;
            }
        }

        #endregion

        #region Encrypt/Decrypt

        public static byte[] Encrypt(this string text, byte[] secretKey, byte[] initVector, SymmetricAlgorithm crypt)
        {
            if (crypt == null)
                crypt = new DESCryptoServiceProvider();

            var encryptor = crypt.CreateEncryptor(secretKey, initVector);

            return Encrypt(text, encryptor);

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "encryptor")]
        public static byte[] Encrypt(this string text, ICryptoTransform encryptor)
        {
            MemoryStream ms = new MemoryStream();

            CryptoStream encStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            // Create a StreamWriter to write a string
            // to the stream.
            StreamWriter sw = new StreamWriter(encStream);

            // Write the plaintext to the stream.
            sw.WriteLine(text);

            // Close the StreamWriter and CryptoStream.
            sw.Close();
            encStream.Close();

            // Get an array of bytes that represents
            // the memory stream.
            byte[] buffer = ms.ToArray();

            // Close the memory stream.
            ms.Close();

            // Return the encrypted byte array.
            return buffer;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "cypher")]
        public static string Decrypt(this byte[] cypherText, byte[] secretKey, byte[] initVector, SymmetricAlgorithm crypt)
        {
            if (crypt == null)
                crypt = new DESCryptoServiceProvider();

            var decryptor = crypt.CreateDecryptor(secretKey, initVector);

            return Decrypt(cypherText, decryptor);
        }

        /// <summary>
        /// Decrypts the specified cypher text.
        /// </summary>
        /// <param name="cypherText">The cypher text serialized in base 64 digits.</param>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="initVector">The init vector.</param>
        /// <param name="crypt">The crypt.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "cypher")]
        public static string Decrypt(this string cypherText, byte[] secretKey, byte[] initVector, SymmetricAlgorithm crypt)
        {
            return cypherText.DeserializeStringToByteArray().Decrypt(secretKey, initVector, crypt);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "decryptor"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "cypher")]
        public static string Decrypt(this byte[] cypherText, ICryptoTransform decryptor)
        {
            // Create a memory stream to the passed buffer.
            MemoryStream ms = new MemoryStream(cypherText);

            // Create a CryptoStream using the memory stream and the 
            // CSP DES key. 
            CryptoStream encStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            // Create a StreamReader for reading the stream.
            StreamReader sr = new StreamReader(encStream);

            // Read the stream as a string.
            string val = sr.ReadLine();

            // Close the streams.
            sr.Close();
            encStream.Close();
            ms.Close();

            return val;
        }

        /// <summary>
        /// Decrypts the specified cypher text.
        /// </summary>
        /// <param name="cypherText">The cypher text serialized in base 64 digits.</param>
        /// <param name="decryptor">The decryptor.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "decryptor"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "cypher")]
        public static string Decrypt(this string cypherText, ICryptoTransform decryptor)
        {
            return cypherText.DeserializeStringToByteArray().Decrypt(decryptor);
        }

        #endregion

        public static bool IsNullOrEmpty(this Guid value)
        {

            return (value == null || value.Equals(Guid.Empty));
        }

        public static bool IsNullOrEmpty(this Array value)
        {
            return (value == null || value.Length == 0);
        }

        public static string ToStringOrEmpty(this Uri value)
        {
            if (value != null)
                return value.ToString();
            else return "";
        }


        public static Guid InitializeId(this Guid id)
        {
            if (id.IsNullOrEmpty())
                id = Guid.NewGuid();
            return id;
        }

        public static String ToCommaDelimitedString(this IEnumerable<String> arr)
        {
            if (arr == null)
                return "";

            StringBuilder sb = new StringBuilder();
            foreach (var s in arr)
            {
                sb.Append(s);
                sb.Append(", ");
            }
            if (sb.Length > 2)
                sb.Remove(sb.Length - 2, 2);
            return sb.ToString();
        }

        public static T GetPropertyValue<T>(this object value, string name)
        {

            var temp = value.GetType().GetProperty(name).GetValue(value, null);
            if (typeof(T) == typeof(String) || typeof(T) == typeof(string))
                temp = (object)temp.ToString();
            return (T)temp;
        }

        public static void SetPropertyValue<T>(this object obj, string name, T value)
        {
            obj.GetType().GetProperty(name).SetValue(obj, value, null);
        }

        public static bool Contains(this int e, int v)
        {
            return ((e & v) == v);
        }

        public static int Age(this DateTime d)
        {
            var age = (int)Math.Round((DateTime.Now - d).TotalDays / 365);
            if (age > 100) age = 0;
            return age;
        }

        public static T Random<T>(this T[] arr)
        {
            var rnd = new Random();
            var c = arr.Length;
            if (c > 0)
                return arr[rnd.Next(0, c)];
            else
                return default(T);
        }

        #region Date

        public static void AllDatePropertiesToLocal(this object value)
        {
            if (value == null)
                return;
            foreach (var prop in (value.GetType().GetProperties()))
            {
                if (prop.PropertyType == typeof(DateTime))
                {
                    DateTime dtValue = (DateTime)prop.GetValue(value, null);
                    prop.SetValue(value, TimeZone.CurrentTimeZone.ToLocalTime(dtValue), null);
                }

                else
                {
                    if (prop.PropertyType.IsArray)
                    {
                        ((System.Collections.IEnumerable)prop.GetValue(value, null)).AllDatePropertiesToLocal();
                    }

                    else
                    {
                        if (prop.PropertyType.Namespace == "Hyz")
                        {
                            prop.GetValue(value, null).AllDatePropertiesToLocal();
                        }
                    }
                }
            }
        }

        public static void AllDatePropertiesToUTC(this object value)
        {
            if (value == null)
                return;
            foreach (var prop in (value.GetType().GetProperties()))
            {
                if (prop.PropertyType == typeof(DateTime))
                {

                    DateTime dtValue = (DateTime)prop.GetValue(value, null);
                    prop.SetValue(value, TimeZone.CurrentTimeZone.ToUniversalTime(dtValue), null);
                }
                else
                {
                    if (prop.PropertyType.IsArray)
                    {
                        ((System.Collections.IEnumerable)prop.GetValue(value, null)).AllDatePropertiesToUTC();
                    }

                    else
                    {
                        if (prop.PropertyType.Namespace == "Hyz")
                        {
                            prop.GetValue(value, null).AllDatePropertiesToUTC();
                        }
                    }
                }
            }
        }

        public static void AllDatePropertiesToLocal(this System.Collections.IEnumerable value)
        {
            if (value == null)
                return;
            foreach (var item in value)
            {
                item.AllDatePropertiesToLocal();
            }
        }

        public static void AllDatePropertiesToUTC(this System.Collections.IEnumerable value)
        {
            if (value == null)
                return;
            foreach (var item in value)
            {
                item.AllDatePropertiesToUTC();
            }
        }

        public static DateTime ToUTC(this DateTime Value)
        {
            var utcData = TimeZone.CurrentTimeZone.ToUniversalTime(Value);
            return utcData;
        }

        public static DateTime ToLocal(this DateTime Value)
        {
            var localData = TimeZone.CurrentTimeZone.ToLocalTime(Value);
            return localData;
        }

        static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0);
        public static long ToUnixTime(this DateTime value)
        {
            return (long) (value - UnixEpoch).TotalSeconds;
        }

        public static long ToJsonTime(this DateTime value)
        {
            return (long)(value - UnixEpoch).TotalMilliseconds;
        }


        public static DateTime ToDateTimeFromUnixTime(this long value)
        {
            return UnixEpoch.AddSeconds(value);
        }

        public static DateTime ToDateTimeFromJsonTime(this long value)
        {
            return UnixEpoch.AddMilliseconds(value);
        }

        #region JulianDay
        static readonly double JD_EQUALITY_MARGIN_IN_DAYS = 1 / (60d * 60d * 1000d * 24d);

        public static bool NearlyEquals(this DateTime dt1, DateTime dt2, double marginInDays)
        {
            if (dt2.Kind != dt1.Kind) throw new ArgumentException(String.Format("The Kind of both dates must be equal. dt1: {0}, dt2: {1}", dt1.Kind, dt2.Kind), "dt2");
            var jd1 = dt1.ToUniversalTime().ToJulianDay();
            var jd2 = dt2.ToUniversalTime().ToJulianDay();
            return Math.Abs(jd1 - jd2) <= marginInDays;
        }

        public static bool NearlyEquals(this DateTime dt1, DateTime dt2)
        {
            return NearlyEquals(dt1, dt2, JD_EQUALITY_MARGIN_IN_DAYS);
        }

        public static double ToJulianDay(this DateTime date)
        {
            if (date.Kind != DateTimeKind.Utc)
                throw new ArgumentException("A date in UTC was expected", "date");
            return JulianDay(date.Year, date.Month, date.Day, date.TimeOfDay.TotalHours, true);
        }

        public static DateTime JulianDayToDate(this double jd)
        {
            int y, m, d; double h;
            GetDate(jd, true, out y, out m, out d, out h);
            return (new DateTime(y, m, d, 0, 0, 0, DateTimeKind.Utc)).AddHours(h);
        }

        #region Meeus' algorithms
        /// <summary>
        /// Calculates the exact amount of Julian day for the given values in Gregorian/Julian calendars.
        /// </summary>
        /// <param name="y">Year</param>
        /// <param name="m">Month</param>
        /// <param name="d">Day</param>
        /// <param name="h">Hour</param>
        /// <param name="IsGregorian">Indicates Whether the y-m-d values are expressed in Gregorian or Julian calendar</param>
        /// <returns></returns>
        public static double JulianDay(int y, int m, int d, double h, bool IsGregorian)
        {
            double D;
            h = h / 24d; D = d + h;
            if (m < 3)
            {
                y = y - 1;
                m = m + 12;
            }

            int a = 0, b = 0;
            if (IsGregorian)
            {
                a = (int)(y / 100d);
                b = 2 - a + (int)(a / 4d);
            }
            return (int)(365.25 * (y + 4716)) + (int)(30.6001 * (m + 1)) + D + b - 1524.5;
        }

        public static void GetDate(double jd, bool IsGregorian, out int Year, out int Month, out int Day, out double Hour)
        {
            jd += .5;
            int z = (int)Math.Floor(jd);
            double F = jd - z;
            int A = 0;
            if (!IsGregorian)
                A = z;
            else
            {
                int alpha = (int)((z - 1867216.25) / 36524.25);
                A = z + 1 + alpha - (int)(alpha / 4d);
            }
            int B = A + 1524; int C = (int)((B - 122.1) / 365.25);
            int D = (int)(365.25 * C); int E = (int)((B - D) / 30.6001);
            double dd = B - D - (int)(30.6001 * E) + F;
            double H = dd - (int)Math.Floor(dd); H *= 24d;

            int mm = 0, yyyy = 0;
            if (E < 13.5)
            {
                mm = E - 1;
            }
            else
            {
                mm = E - 13;
            }
            if (mm > 2.5)
            {
                yyyy = C - 4716;
            }
            else
            {
                yyyy = C - 4715;
            }
            Year = (int)yyyy; Month = (int)mm; Day = (int)dd; Hour = H;

        }

        /// <summary>
        /// Converts the given Julian day into its corresponding calendar date in Gregorian or Julian calendar.
        /// </summary>
        /// <param name="jd">Julian day</param>
        /// <param name="IsGregorian">Whether to use Gregorian or Julian calendar</param>
        /// <param name="Year">Year</param>
        /// <param name="Month">Month</param>
        /// <param name="Day">Day</param>
        /// <param name="Hour">Hour</param>
        /// <param name="Minute">Minute</param>
        /// <param name="Second">Second</param>
        public static void GetDate(double jd, bool IsGregorian, out int Year, out int Month, out int Day, out int Hour, out int Minute, out int Second, out int Milisecond)
        {
            jd += .5;
            int z = (int)Math.Floor(jd);
            double F = jd - z;
            int A = 0;
            if (!IsGregorian)
                A = z;
            else
            {
                int alpha = (int)((z - 1867216.25) / 36524.25);
                A = z + 1 + alpha - (int)(alpha / 4d);
            }
            int B = A + 1524; int C = (int)((B - 122.1) / 365.25);
            int D = (int)(365.25 * C); int E = (int)((B - D) / 30.6001);
            double dd = B - D - (int)(30.6001 * E) + F;
            double H = dd - (int)Math.Floor(dd); H *= 24;
            double N = H - (int)(H); N = N * 60;
            double S = N - (int)N; S *= 60;
            double ms = S - (int)S; ms *= 1000;
            int mm = 0, yyyy = 0;
            if (E < 13.5)
            {
                mm = E - 1;
            }
            else
            {
                mm = E - 13;
            }
            if (mm > 2.5)
            {
                yyyy = C - 4716;
            }
            else
            {
                yyyy = C - 4715;
            }
            Year = (int)yyyy; Month = (int)mm; Day = (int)dd; Hour = (int)H; Minute = (int)N; Second = (int)S; Milisecond = (int)ms; // (int) S;
        }
        #endregion
        #endregion

        #endregion

        #region Format
        public static string FormatOrdinal(this int num)
        {
            switch (num % 100)
            {
                case 11:
                case 12:
                case 13:
                    return num.ToString() + "th";
            }

            switch (num % 10)
            {
                case 1:
                    return num.ToString() + "st";
                case 2:
                    return num.ToString() + "nd";
                case 3:
                    return num.ToString() + "rd";
                default:
                    return num.ToString() + "th";
            }

        }
        #endregion

        public static IEnumerable<IEnumerable<T>> Chunk<T>(this IEnumerable<T> coll, int size)
        {
            int took = 0;
            int length;
            IEnumerable<T> take;
            do
            {
                take = coll.Skip(took).Take(size);
                length = take.Count();
                took += length;
                if (length == 0)
                    yield break;
                yield return take.AsEnumerable();
            } while (length > 0);
        }
    }
}
