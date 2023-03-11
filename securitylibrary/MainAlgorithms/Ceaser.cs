using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = string.Empty;
            plainText= plainText.ToUpper();

            for (int i = 0; i < plainText.Length; i++)
            {
                int c = (((plainText[i] - 'A') + key) % 26) + 'A';
                cipherText += (char)c;
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = string.Empty;
            cipherText = cipherText.ToUpper();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = (((cipherText[i] - 'A' + 26) - key) % 26) + 'A';
                plainText += (char)c;
            }

            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText= plainText.ToUpper();
            cipherText= cipherText.ToUpper();

            for(int i = 0; i < 26; i++)
            {
                string plain = Decrypt(cipherText, i);

                if (string.Compare(plain, plainText) == 0) 
                {
                    
                    return i;
                }

            }
            return 0;
        }
    }
}
