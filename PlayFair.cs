using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        static string letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        public string Decrypt(string cipherText, string key)
        {
            string plainText = string.Empty;
            cipherText = cipherText.ToUpper();
            key= key.ToUpper();

            HashSet<char> tableSet = new HashSet<char>();

            for (int i = 0; i < key.Length; i++)
                tableSet.Add(key[i]);

            tableSet.UnionWith(letters);

            List<char> table = tableSet.ToList<char>();
            cipherText = cipherText.Replace("J", "I");

            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                int frst = table.IndexOf(cipherText[i]);
                int scnd = table.IndexOf(cipherText[i + 1]);

                int x1 = frst % 5;
                int y1 = frst / 5;

                int x2 = scnd % 5;
                int y2 = scnd / 5;

                if (x1 == x2)
                {
                    plainText += (table[x1 + 5 * (((y1 - 1) + 5) % 5)]);
                    plainText += (table[x1 + 5 * (((y2 - 1) + 5) % 5)]);

                }
                else if (y1 == y2)
                {
                    plainText += (table[(((x1 - 1) + 5) % 5) + 5 * y2]);
                    plainText += (table[(((x2 - 1) + 5) % 5) + 5 * y2]);
                }
                else
                {
                    plainText += (table[x2 + 5 * y1]);
                    plainText += (table[x1 + 5 * y2]);
                }
            }

            for (int i = 1; i < plainText.Length - 1; i+=2)
            {
                if (plainText[i] == 'X' && plainText[i + 1] == plainText[i - 1])
                {
                    plainText = plainText.Remove(i, 1);
                    i++;
                }
            }

            if (plainText[plainText.Length - 1] == 'X')
                plainText = plainText.Remove(plainText.Length - 1);

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = string.Empty;
            plainText = plainText.ToUpper();
            key= key.ToUpper();

            for (int i = 0; i < plainText.Length - 1; i+=2)
            {
                if (plainText[i] == plainText[i + 1])
                    plainText = plainText.Insert(i+1, "X");
            }

            if (plainText.Length %2 == 1) plainText += 'X';

            HashSet<char> tableSet = new HashSet<char>();

            for (int i = 0; i < key.Length; i++)
                tableSet.Add(key[i]);

            tableSet.UnionWith(letters);

            List<char> table = tableSet.ToList<char>();
            plainText= plainText.Replace("J", "I");

            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                int frst = table.IndexOf(plainText[i]);
                int scnd = table.IndexOf(plainText[i + 1]);

                int x1 = frst % 5;
                int y1 = frst / 5;

                int x2 = scnd % 5;
                int y2 = scnd / 5;

                if (x1 == x2)
                {
                    cipherText += (table[x1 + 5 * ((y1 + 1) % 5)]);
                    cipherText += (table[x1 + 5 * ((y2 + 1) % 5)]);

                }
                else if (y1 == y2)
                {
                    cipherText += (table[((x1 + 1) % 5) + 5 * y2]);
                    cipherText += (table[((x2 + 1) % 5) + 5 * y2]);
                }
                else
                {
                    cipherText += (table[x2 + 5 * y1]);
                    cipherText += (table[x1 + 5 * y2]);
                }
            }

            return cipherText;
        }
    }
}
