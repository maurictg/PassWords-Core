/* EasyEncrypt
 * 
 * Copyright (c) 2019 henkje
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Easy
{
    public class Encryption
    {
        /// <summary>
        /// Algorithm for encryption and decryption data.
        /// </summary> 
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Create class with an already set up algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm wich is alreay set up properly</param>
        public Encryption(SymmetricAlgorithm algorithm)
            => this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
        /// <summary>
        /// Create class with an algorithm and overide the key for the selected algorithm.
        /// </summary>
        /// <param name="algorithm">New algorithm</param>
        /// <param name="key">Generated key</param>
        public Encryption(SymmetricAlgorithm algorithm, byte[] key)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (key == null) throw new ArgumentException("Invalid key, key is null.");
            if (!this.algorithm.ValidKeySize(key.Length * 8)) throw new ArgumentException("Invalid key, key has an invalid size.");
            this.algorithm.Key = key;
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm.
        /// </summary>
        /// <param name="algorithm">New algorithm</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        public Encryption(SymmetricAlgorithm algorithm, string password, string salt, int iterations = 10000)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            this.algorithm.Key = CreateKey(this.algorithm, password, salt, iterations);
        }
        /// <summary>
        /// Create class and create a new key for the passed algorithm with a fixed keysize.
        /// </summary>
        /// <param name="algorithm">new algorithm</param>
        /// <param name="keySize">Keysize in bits(8 bits = 1 byte)</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        public Encryption(SymmetricAlgorithm algorithm, int keySize, string password, string salt, int iterations = 10000)
        {
            this.algorithm = algorithm ?? throw new ArgumentException("Invalid algorithm, algorithm is null.");
            if (!this.algorithm.ValidKeySize(keySize)) throw new ArgumentException("Invalid key, key has an invalid size.");
            this.algorithm.Key = CreateKey(keySize, password, salt, iterations);
        }

        /// <summary>
        /// Encrypt a string and decode with UTF8.
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text(base64 string)</returns>
        public string Encrypt(string text)
            => Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(text ?? throw new ArgumentException("Could not decrypt text: Text can't be null."))));
        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <param name="encoder">Encoding used to convert string to byte[]</param>
        /// <returns>Encrypted text(base64 string)</returns>
        public string Encrypt(string text, Encoding encoder)
            => Convert.ToBase64String(Encrypt(encoder.GetBytes(text ?? throw new ArgumentException("Could not decrypt text: Text can't be null."))));
        /// <summary>
        /// Encrypt a byte[].
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted data(byte[])</returns>
        public byte[] Encrypt(byte[] data)
        {
            if (data == null) throw new Exception("Could not encrypt data: Data can't be null.");

            algorithm.GenerateIV();//Genarate new random IV.

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(algorithm.IV, 0, algorithm.IV.Length);//Write IV to ms(first 16 bytes)
                using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateEncryptor(algorithm.Key, algorithm.IV), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Decrypt a string and decode with UTF8.
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text(string encoded with UTF8)</returns>
        public string Decrypt(string text)
            => Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(text ?? throw new ArgumentException("Could not decrypt text: Text can't be null."))));
        /// <summary>
        /// Decrypt a string.
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <param name="encoder">Encoding used to convert byte[] to string</param>
        /// <returns>Decrypted text(string encoded with Encoder)</returns>
        public string Decrypt(string text, Encoding encoder)
            => encoder.GetString(Decrypt(Convert.FromBase64String(text ?? throw new ArgumentException("Could not decrypt text: Text can't be null."))));
        /// <summary>
        /// Decrypt byte[].
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] data)
        {
            if (data == null) throw new ArgumentException("Could not encrypt data: Data can't be null.");

            using (MemoryStream ms = new MemoryStream(data))
            {
                byte[] IV = new byte[algorithm.IV.Length];
                ms.Read(IV, 0, IV.Length);//Get IV from ms(first 16 bytes)
                algorithm.IV = IV;

                using (CryptoStream cs = new CryptoStream(ms, algorithm.CreateDecryptor(algorithm.Key, algorithm.IV), CryptoStreamMode.Read))
                {
                    byte[] decrypted = new byte[data.Length];
                    int byteCount = cs.Read(decrypted, 0, data.Length);
                    return new MemoryStream(decrypted, 0, byteCount).ToArray();
                }
            }
        }

        /// <summary>
        /// Return the current key.
        /// </summary>
        /// <returns>Encryption key</returns>
        public byte[] GetKey()
            => algorithm.Key;

        /*static members*/
        /// <summary>
        /// Create a new encryption key with PBKDF2 and a selected keysize.
        /// </summary>
        /// <param name="keySize">Keysize in bits(8 bits = 1 byte)</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        /// <returns>Encryption key</returns>
        public static byte[] CreateKey(int keySize, string password, string salt, int iterations = 10000)
        {
            if (keySize <= 0) throw new ArgumentException("Could not create key: Invalid KeySize.");
            else if (salt.Length < 8) throw new ArgumentException("Could not create key: Salt is to short.");
            else if (string.IsNullOrEmpty(password)) throw new ArgumentException("Could not create key: Password can't be empty.");
            else if (iterations <= 0) throw new ArgumentException("Could not create key: Invalid Iterations count.");

            return new Rfc2898DeriveBytes(password,
                Encoding.UTF8.GetBytes(salt),//Convert salt to byte[]
                iterations).GetBytes(keySize / 8);
        }
        /// <summary>
        /// Create a new encryption key with PBKDF2 for the selected Algorithm.
        /// </summary>
        /// <param name="algorithm">Algorithm is used to get the keysize</param>
        /// <param name="password">Password, used to generate key</param>
        /// <param name="salt">Salt, used to make generated key more random(min 8 characters)</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete a key</param>
        /// <returns>Encryption key</returns>
        public static byte[] CreateKey(SymmetricAlgorithm algorithm, string password, string salt, int iterations = 10000)
            => CreateKey(algorithm.LegalKeySizes[0].MaxSize, password, salt, iterations);
    }

    public static class Hashing
    {
        private const int defaultIterations = 50000;
        private const int defaultLength = 32;

        /// <summary>
        /// Hash a string with PBKDF2.
        /// </summary>
        /// <param name="input">String to hash</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete the hash</param>
        /// <param name="length">Lenth of the hash, the output will also contains the salt</param>
        /// <returns>The generated salt+hash</returns>
        public static string Hash(string input, int iterations = defaultIterations, int length = defaultLength)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Could not hash input: Input is empty.");
            else if (iterations <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Iterations can't be negative or 0.");
            else if (length <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Length can't be negative or 0.");

            //Create salt of 16 byte's.
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);

            //Create hash of [length] byte's.
            byte[] hash = new Rfc2898DeriveBytes(input, salt, iterations).GetBytes(length);

            //Combine salt and hash.
            byte[] combinedBytes = new byte[16 + length];
            Buffer.BlockCopy(salt, 0, combinedBytes, 0, 16);//Add salt.
            Buffer.BlockCopy(hash, 0, combinedBytes, 16, length);//Add hash.

            //Return combinedBytes as base64 string.
            return Convert.ToBase64String(combinedBytes);
        }

        /// <summary>
        /// Hash a byte[] with PBKDF2.
        /// </summary>
        /// <param name="input">Byte[] to hash</param>
        /// <param name="iterations">Rounds PBKDF2 will make to genarete the hash</param>
        /// <param name="length">Lenth of the hash, the output will also contains the salt</param>
        /// <returns>The generated salt+hash</returns>
        public static byte[] Hash(byte[] input, int iterations = defaultIterations, int length = defaultLength)
        {
            if (input == null)
                throw new ArgumentNullException("Could not hash input: Input is null.");
            else if (iterations <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Iterations can't be negative or 0.");
            else if (length <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Length can't be negative or 0.");

            //Create salt of 16 byte's.
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);

            //Create hash of [length] byte's.
            byte[] hash = new Rfc2898DeriveBytes(input, salt, iterations).GetBytes(length);

            //Combine salt and hash.
            byte[] combinedBytes = new byte[16 + length];
            Buffer.BlockCopy(salt, 0, combinedBytes, 0, 16);//Add salt.
            Buffer.BlockCopy(hash, 0, combinedBytes, 16, length);//Add hash.

            //Return combinedBytes;
            return combinedBytes;
        }

        /// <summary>
        /// Compare hashed string with another string.
        /// </summary>
        /// <param name="hashedInput">Hashed string</param>
        /// <param name="input">String to compare with hashedInput</param>
        /// <param name="iterations">Rounds PBKDF2 made to generate hashedInput</param>
        /// <returns>boolean, true if hashedInput is the same as input</returns>
        public static bool Verify(string hashedInput, string input, int iterations = defaultIterations)
        {
            if (string.IsNullOrEmpty(hashedInput))
                throw new ArgumentException("Could not hash input: HashedInput is empty.");
            else if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Could not hash input: Input is empty.");
            else if (iterations <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Iterations can't be negative or 0.");

            //Get byte's from hashedInput.
            byte[] hashedBytes = Convert.FromBase64String(hashedInput);

            //Get the length of the hash.
            int length = hashedBytes.Length - 16;

            //Get the salt from hashedBytes.
            byte[] salt = new byte[16];
            Buffer.BlockCopy(hashedBytes, 0, salt, 0, 16);

            //Generate hash of input, to compare it with hashedBytes
            byte[] hash = new Rfc2898DeriveBytes(input, salt, iterations).GetBytes(length);

            //Compare the result's.
            for (int i = 0; i < length; i++)
                if (hashedBytes[i + 16] != hash[i])
                    return false;

            return true;
        }

        /// <summary>
        /// Compare hashed byte[] with another byte[].
        /// </summary>
        /// <param name="hashedBytes">Hashed byte[]</param>
        /// <param name="input">byte[] to compare with hashedBytes</param>
        /// <param name="iterations">Rounds PBKDF2 made to generate hashedBytes</param>
        /// <returns>boolean, true if hashedBytes is the same as input</returns>
        public static bool Verify(byte[] hashedBytes, byte[] input, int iterations = defaultIterations)
        {
            if (hashedBytes == null)
                throw new ArgumentException("Could not hash input: hashedBytes is null.");
            else if (input == null)
                throw new ArgumentException("Could not hash input: Input is empty.");
            else if (iterations <= 0)
                throw new ArgumentOutOfRangeException("Could not hash input: Iterations can't be negative or null.");

            //Get the length of the hash.
            int length = hashedBytes.Length - 16;

            //Get the salt from HashedInputBytes.
            byte[] salt = new byte[16];
            Buffer.BlockCopy(hashedBytes, 0, salt, 0, 16);

            //Generate hash of Input, to compare it with hashedBytes.
            byte[] hash = new Rfc2898DeriveBytes(input, salt, iterations).GetBytes(length);

            //Compare the result's.
            for (int i = 0; i < length; i++)
                if (hashedBytes[i + 16] != hash[i])
                    return false;

            return true;
        }
    }
}