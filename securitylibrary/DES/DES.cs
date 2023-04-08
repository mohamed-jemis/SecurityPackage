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
        int[] exp_d = new int[]
        {
            32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1
        };

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //do the initial permutation
            string plain_text_matrix = initial_permutation(plainText,IP);
            //divide the plain text to L and R 
            string LPT = plain_text_matrix.Substring(0, 32);
            string RPT = plain_text_matrix.Substring(32, 32);
            //perform the 16 round 
            for(int i=0;i<16;i++)
            {
                //el expansion da ka2nena bn3ml padding lel RPT 3shan n3rf n3mlha xor m3 l key el huwa 
                //48 bit huwa kman we bn3ml kda according to el exp_d zaiha zai el ip kda nafs l fekra
                string right = right_expansion(RPT);
            }
            return;
        }

        private string right_expansion(string text)
        {
            string new_text = "";
            for(int i=0;i<48;i++)
            {
                new_text += text[exp_d[i] - 1];
            }
            return new_text;
        }

        private string initial_permutation(string plainText,int[] IP)
        {
            string result="";
            for(int i=0;i<plainText.Length;i++)
            {
                result += plainText[IP[i] - 1];
            }
            return result;
        }
        private string XOR(string text,string key)
        {
            string result = "";
            for(int i=0;i<text.Length;i++)
            {
                if (text[i] != key[i])
                    result += '1';
                else
                    result += '0';
            }
            return result;
        }
    }
}
