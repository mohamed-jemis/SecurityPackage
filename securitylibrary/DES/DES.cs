using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        Dictionary<char, string> convertDict = new Dictionary<char, string>()
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


        int[] PC1 = new int[]
        { 
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        int[] shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        int[] PC2 = new int[]
        {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        int[] IP = new int[]
        { 
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        int[] FP = new int[]
        { 
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        int[] exp_d = new int[]
        {
            32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1
        };

        int[] P = new int[]
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        };

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = string.Empty;

            // Converting from hex to bin
            string binKey = hex_to_bin(key);
            string binCipher = hex_to_bin(cipherText);

            // Key Creation
            List<string> subkeys = key_creation(binKey);

            // Decoding message
            // initial permutation
            string lr_prev = permutation(binCipher, FP);
            string lr_final = string.Empty;

            // rounds
            for (int i = 15; i >= 0; i--)
            {
                string l = lr_prev.Substring(32);
                string r = XOR(mangler_func(l/*prev R*/, subkeys[i]), lr_prev.Substring(0, 32));

                lr_prev = l + r;

                // Swap l and r after final round
                if (i == 0)
                    lr_final = r + l;
            }

            // final permutation
            plainText = permutation(lr_final, FP);


            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            //do the initial permutation
            string plain_text_matrix = permutation(plainText, IP);
            //divide the plain text to L and R 
            string LPT = plain_text_matrix.Substring(0, 32);
            string RPT = plain_text_matrix.Substring(32, 32);
            //perform the 16 round 
            for (int i = 0; i < 16; i++)
            {
                //el expansion da ka2nena bn3ml padding lel RPT 3shan n3rf n3mlha xor m3 l key el huwa 
                //48 bit huwa kman we bn3ml kda according to el exp_d zaiha zai el ip kda nafs l fekra
                string right = right_expansion(RPT);
            }
            return null;
        }

        private string hex_to_bin(string text)
        {
            string hex = string.Empty;

            for (int i = 2; i < text.Length; i++)
            {
                hex += convertDict[text[i]];
            }

            return hex;
        }

        private List<string> key_creation(string key)
        {
            string kPlus = permutation(key, PC1);

            string c_prev = kPlus.Substring(0, 28);
            string d_prev = kPlus.Substring(28);

            List<string> subkeys = new List<string>();

            for (int i = 1; i <= 16; i++)
            {
                string c = c_prev.Substring(shifts[i - 1]) + c_prev.Substring(0, shifts[i - 1]);
                string d = d_prev.Substring(shifts[i - 1]) + d_prev.Substring(0, shifts[i - 1]);
                string cd = c + d;
                string subkey = string.Empty;

                subkeys.Add(permutation(cd, PC2));

                c_prev = c;
                d_prev = d;
            }

            return subkeys;
        }

        private string right_expansion(string text)
        {
            string new_text = "";
            for (int i = 0; i < 48; i++)
            {
                new_text += text[exp_d[i] - 1];
            }
            return new_text;
        }

        private string permutation(string text, int[] P)
        {
            string result = "";
            for (int i = 0; i < text.Length; i++)
            {
                result += text[P[i] - 1];
            }
            return result;
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

        private string mangler_func(string right, string key)
        {
            string expanded = right_expansion(right);
            string xor_res = XOR(expanded, key);
            string reduced = s_box(xor_res);
            string permuted = permutation(reduced, P);

            return permuted;

        }
        private string s_box(string text) 
        {
            return null;
        }
        
    }
}
