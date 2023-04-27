using SecurityLibrary.DES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        static Dictionary<char, string> HexToBinDict = new Dictionary<char, string>()
        {
            { '0', "0000" },
            { '1', "0001" },
            { '2', "0010" },
            { '3', "0011" },
            { '4', "0100" },
            { '5', "0101" },
            { '6', "0110" },
            { '7', "0111" },
            { '8', "1000" },
            { '9', "1001" },
            { 'A', "1010" },
            { 'B', "1011" },
            { 'C', "1100" },
            { 'D', "1101" },
            { 'E', "1110" },
            { 'F', "1111" },
        };

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = string.Empty;
            bool isHexa = false;

            // Coverting Hexa to ASCII
            if (cipherText[0] == '0')
            {
                cipherText = hex_to_ascii(cipherText.ToUpper());
                key = hex_to_ascii(key.ToUpper());
                plainText += "0x";
                isHexa = true;
            }

            // Part 1: Key Creation
            // S and T intialization
            int[] S = new int[256];
            int[] T = new int[256];

            for (int i = 0; i < 256; i++) 
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }

            // Initial Permutation of S
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                swap(ref S[j], ref S[i]);
            }

            // Stream Generation (Second Permutation of S)
            int ii = 0; j = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                ii = (ii + 1) % 256;
                j = (j + S[ii]) % 256;

                swap(ref S[j], ref S[ii]);

                int t = (S[ii] + S[j]) % 256;

                // Part 2: Decryption

                string k_bin = Convert.ToString(S[t], 2);
                k_bin = k_bin.PadLeft(8, '0');

                string curr_byte = ascii_to_bin(cipherText[i].ToString());
                string plainByte = XOR(curr_byte, k_bin);

                if (isHexa)
                    plainText += bin_to_hex(plainByte);
                else
                    plainText += bin_to_ascii(plainByte);

            }

            return plainText;
        }

        public override  string Encrypt(string plainText, string key)
        {
            return Decrypt(plainText, key);
        }

        // Helper Functions
        private void swap(ref int left, ref int right)
        {
            int temp;
            temp = left;
            left = right;
            right = temp;
        }
        private string XOR(string text, string key)
        {
            string result = "";
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] != key[i])
                    result += '1';
                else
                    result += '0';
            }
            return result;
        }

        private string ascii_to_bin(string text)
        {
            string bin = string.Empty;

            for (int i = 0; i < text.Length; i++)
            {
                byte[] asciiBytes = Encoding.Unicode.GetBytes(text[i].ToString());
                string binaryLetter = Convert.ToString(asciiBytes[0], 2).PadLeft(8, '0');
                bin += binaryLetter;
            }
            return bin;
        }

        private string hex_to_bin(string text)
        {
            string bin = string.Empty;

            for (int i = 2; i < text.Length; i++)
            {
                bin += HexToBinDict[text[i]];
            }

            return bin;
        }

        private string bin_to_ascii(string text)
        {
            string ascii = "";

            for (int i = 0; i < text.Length; i += 8)
            {
                string binaryChar = text.Substring(i, 8);
                byte asciiCode = Convert.ToByte(binaryChar, 2);
                char c = Convert.ToChar(asciiCode);
                ascii += c;
            }

            return ascii;
        }

        private string hex_to_ascii(string text)
        {
            return bin_to_ascii(hex_to_bin(text));
        }

        private string bin_to_hex(string text)
        {
            Dictionary<string, char> BinToHexDict = RC4.HexToBinDict.ToDictionary(pair => pair.Value, pair => pair.Key);

            string hex = "";

            for (int i = 0; i < text.Length; i += 4)
            {
                hex += BinToHexDict[text.Substring(i, 4)];
            }

            return hex;
        }
    }
}
