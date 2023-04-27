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
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES Des_ = new DES();
            String step_1 = Des_.Decrypt(cipherText, key[0]);
            string step_2 = Des_.Encrypt(step_1, key[1]);
            String step_3 = Des_.Decrypt(step_2, key[0]);
            return step_3;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES Des_ = new DES();
            String step_1 = Des_.Encrypt(plainText, key[0]);
            string step_2 = Des_.Decrypt(step_1, key[1]);
            String step_3 = Des_.Encrypt(step_2, key[0]);
            return step_3;

        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
