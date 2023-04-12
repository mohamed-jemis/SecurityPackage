using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        Dictionary<char, string> convert_hex_Dict = new Dictionary<char, string>()
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
        Dictionary<string, char> convert_binary_Dict = new Dictionary<string, char>()
        {
            { "0000",'0'},
            { "0001",'1'},
            { "0010",'2'},
            { "0011",'3'},
            { "0100",'4'},
            { "0101",'5'},
            { "0110",'6'},
            { "0111",'7'},
            { "1000",'8'},
            { "1001",'9'},
            { "1010",'A'},
            { "1011",'B'},
            { "1100",'C'},
            { "1101",'D'},
            { "1110",'E'},
            { "1111",'F'},
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
            40, 8, 48, 16, 56, 24, 64,32,
            39, 7, 47, 15, 55,23, 63, 31,
            38, 6, 46,14, 54, 22, 62, 30,
            37,5, 45, 13, 53, 21, 61,29,
            36, 4, 44, 12, 52,20, 60, 28,
            35, 3, 43,11, 51, 19, 59, 27,
            34,2, 42, 10, 50, 18, 58,26,
            33, 1, 41, 9, 49,17, 57, 25
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
        int[] sbox_permutation = new int[]
        {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };
        int[] KP = new int[]
        {
            57, 49, 41, 33, 25,17, 9,
            1, 58, 50, 42, 34, 26,18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63,55, 47, 39, 31, 23, 15,
            7, 62,54, 46, 38, 30, 22,
            14, 6, 61,53, 45, 37, 29,
            21, 13, 5, 28,20, 12, 4
        };
        int[] KC = new int[]
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
        static int[,,] sboxes = new int[,,]
        {
            {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };
        int[] shifting_bits = new int[]
        {
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        };

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = string.Empty;

            // Converting from hex to bin
            string binKey = hexa_to_binary(key);
            string binCipher = hexa_to_binary(cipherText);

            // Key Creation
            List<string> subkeys = key_creation(binKey);
            // Decoding message
            // initial permutation
            string lr_init = permutation(binCipher, IP);
            string lr_final = string.Empty;

            string l = lr_init.Substring(0, 32);
            string r = lr_init.Substring(32, 32);

            // rounds
            for (int i = 15; i >= 0; i--)
            {
                l = XOR(mangler_func(r, subkeys[i]), l);
                swap(ref l, ref r);
            }
            swap(ref l, ref r);

            lr_final = l + r;

            // final permutation
            string binPlainText = permutation(lr_final, FP);
            plainText = binary_to_hex(binPlainText);

            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            //convert the pt and key to binary
            string binary_pt = hexa_to_binary(plainText);
            string binary_key = hexa_to_binary(key);
            //do the initial permutation
            string plain_text_permutated = permutation(binary_pt, IP);
            //divide the plain text to LPT and RPT 
            string LPT = plain_text_permutated.Substring(0, 32);
            string RPT = plain_text_permutated.Substring(32, 32);
            //do the first key permutation
            string key_permutated = permutation(binary_key, KP);
            List<string> keys = generate_keys(key_permutated);
            //perform the 16 round 
            for (int i = 0; i < 16; i++)
            {
                //el expansion da ka2nena bn3ml padding lel RPT 3shan n3rf n3mlha xor m3 l key el huwa 
                //48 bit huwa kman we bn3ml kda according to el exp_d zaiha zai el ip kda nafs l fekra
                string expanded_right = permutation(RPT, exp_d);
                string xored_right = XOR(expanded_right, keys[i]);
                //xored_right should be sboxed
                string sboxed_right = s_box(xored_right);
                string permutated_sboxed_right = permutation(sboxed_right, sbox_permutation);

                LPT = XOR(LPT, permutated_sboxed_right);
                swap(ref LPT, ref RPT);
            }
            swap(ref LPT, ref RPT);
            plainText = LPT + RPT;
            string result = permutation(plainText, FP);
            return binary_to_hex(result);
        }

        private string permutation(string plainText, int[] permutation_matrix)
        {
            string result = "";
            for (int i = 0; i < permutation_matrix.Length; i++)
            {
                result += plainText[permutation_matrix[i] - 1];
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
            string expanded = permutation(right, exp_d);
            string xor_res = XOR(expanded, key);
            string reduced = s_box(xor_res);
            string permuted = permutation(reduced, sbox_permutation);
            return permuted;
        }


        private List<string> generate_keys(string key)
        {
            List<string> result = new List<string>();
            string left_key = key.Substring(0, 28);
            string right_key = key.Substring(28, 28);

            for (int i = 0; i < 16; i++)
            {
                left_key = shift_left(left_key, shifting_bits[i]);
                right_key = shift_left(right_key, shifting_bits[i]);
                string complete_key = left_key + right_key;
                string compressed_key = permutation(complete_key, KC);
                result.Add(compressed_key);
            }
            return result;
        }

        private List<string> key_creation(string key)
        {
            string kPlus = permutation(key, KP);

            string c = kPlus.Substring(0, 28);
            string d = kPlus.Substring(28);

            List<string> subkeys = new List<string>();

            for (int i = 0; i < 16; i++)
            {

                c = shift_left(c, shifting_bits[i]);
                d = shift_left(d, shifting_bits[i]);
                string cd = c + d;

                subkeys.Add(permutation(cd, KC));
            }

            return subkeys;
        }

        private string shift_left(string key, int n)
        {

            string result = key;
            for (int i = 0; i < n; i++)
            {
                result = result.Substring(1, key.Length - 1) + result.Substring(0, 1);
            }
            return result;
        }
        private void swap(ref string left, ref string right)
        {
            string temp;
            temp = left;
            left = right;
            right = temp;
        }
        private string s_box(string word)
        {
            String[] str_list = new String[8];
            int counter = 0;

            for (int i = 0; i < 48; i += 6)
            {
                str_list[counter] = word.Substring(i, 6);
                counter++;
            }

            string final = "";

            for (int i = 0; i < 8; i++)
            {
                char[] chars = { str_list[i][0], str_list[i][5] };
                string s1 = new string(chars);

                String s2 = str_list[i].Substring(1, 4);

                int decimalValue1 = Convert.ToInt32(s1, 2);
                int decimalValue2 = Convert.ToInt32(s2, 2);
                // value get from s box 
                int value = sboxes[i, decimalValue1, decimalValue2];
                /*if (value <= 7)
                    final += "0";
                if(value)*/
                string binary2 = Convert.ToString(value, 2);
                if (binary2.Length < 4)
                    binary2 = binary2.PadLeft(4, '0');

                final += binary2;
            }
            return final;
        }
        private string hexa_to_binary(string text)
        {
            string hex = string.Empty;
            for (int i = 2; i < text.Length; i++)
            {
                hex += convert_hex_Dict[text[i]];
            }
            return hex;
        }
        private string binary_to_hex(string binaryvalue)
        {
            //not mine but for test
            var hex = string.Join("",
                Enumerable.Range(0, binaryvalue.Length / 8)
                    .Select(i => Convert.ToByte(binaryvalue.Substring(i * 8, 8), 2).ToString("X2")));
            return "0x" + hex;

        }
    }
}
