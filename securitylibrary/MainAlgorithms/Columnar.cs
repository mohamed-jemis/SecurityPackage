using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            Console.WriteLine(plainText + " " + cipherText);

            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            int len = 0;

            if (cipherText[0] == cipherText[1])
                len = plainText.IndexOf(cipherText[1], 3) - plainText.IndexOf(cipherText[0], 2);
            else
                len = plainText.IndexOf(cipherText[1]) - plainText.IndexOf(cipherText[0]);

            int[] key = Enumerable.Range(1, len).ToArray<int>();
            List<int> finalKey = new List<int>();

            keyTrail(plainText, cipherText, key, len, len, ref finalKey);

            return finalKey;
            
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToUpper();
            string cipherTable = string.Empty;
            string plainText = string.Empty;

            int len = key.Count;
            int height = cipherText.Length / len;
            
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < cipherText.Length; j++)
                {
                    if (i + j * height >= cipherText.Length)
                        continue;

                    cipherTable += cipherText[i + j * height];
                }
            }

            for (int j = 0; j < height; j++)
            {
                for (int i = 0; i < len; i++)
                {
                    plainText += cipherTable[(key[i] - 1) + len*j];
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.ToUpper();
            string cipherText = string.Empty;

            int len = key.Count;
            int height = (int)Math.Ceiling((double) plainText.Length / len);
            
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < height; j++)
                {
                    int indx = key.IndexOf(i + 1) + len * j;

                    if (indx >= plainText.Length)
                        cipherText += 'x';
                    else
                        cipherText += plainText[indx];
                }
            }

            return cipherText;
        }

        bool flag= false;
        static void keyTrail(string plainText, string cipherText, int[] a, int size, int n, ref List<int> finalKey)
        {
            Columnar c = new Columnar();

            if (size == 1)
            {
                List<int> currKey = a.ToList<int>();
                string cipher = c.Encrypt(plainText, currKey);
                cipher = cipher.Replace("x", "");


                if (string.Compare(cipher, cipherText) == 0)
                {
                    finalKey = new List<int>(currKey);
                    c.flag= true;
                    return;
                }

            }

            if (c.flag) return;

            for (int i = 0; i < size; i++)
            {
                keyTrail(plainText, cipherText, a, size - 1, n, ref finalKey);

                if (size % 2 == 1)
                {
                    int temp = a[0];
                    a[0] = a[size - 1];
                    a[size - 1] = temp;
                }

                else
                {
                    int temp = a[i];
                    a[i] = a[size - 1];
                    a[size - 1] = temp;
                }
            }
        }

    }
}
