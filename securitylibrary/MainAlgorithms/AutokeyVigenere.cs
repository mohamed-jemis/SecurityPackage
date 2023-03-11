using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[,] fill_vigenere(int s)
        {
            char[,] vegenere = new char[26, 26];
            for (int i = 0; i < s;i++)
            {
                for (int j=0;j<s;j++)
                {
                    vegenere[i, j] = (char)('A' + (i + j) % s);       
                }
            }
            return vegenere;
        }
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            char[,] vegenere = fill_vigenere(26);
            for (int i =0; i<plainText.Length;i++)
            {
                int row = plainText[i] - 97;
                for(int j = 0;j<26;j++)
                {
                    if(vegenere[row,j]==cipherText[i])
                    {
                        char temp = (char)('a' + j);
                        key += temp;
                        break;
                    }
                }
            }
            //find the longest subset from the end of the key and plaintext
            int index = 0;
            for(int i=0;i<key.Length;i++)
            {
                if(key[i]==plainText[0])
                {
                    string possible_substring = key.Substring(i);
                    if(plainText.Contains(possible_substring))
                    {
                        index = i;
                        break;
                    }
                }
            }
            key = key.Remove(index);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // get the p.t and stop when the key size ends 
            //complete the needed key with the p.t that you got 
            char[,] vegenere = fill_vigenere(26);
            string plain_text = "";
            key = key.ToLower();
            int i = 0;
            while(cipherText.Length>plain_text.Length)
            {
                int column = key[i]-97;
                for (int j=0;j<26;j++)
                {
                    if(vegenere[j,column]==cipherText[i])
                    {
                        char temp = (char)('a' + j);
                        plain_text +=temp;
                        key += plain_text[i];
                        i++;
                        break;
                    }
                }
            }
            return plain_text;
         /*   for (int i=0;i<key.Length;i++)
           // {
             //   int column = key[i]-97;
               // for (int j=0;j<26;j++)
                //{
                    if (vegenere[j, column] == cipherText[i])
                    { 
                        char temp = (char)('A' + j);
                        p_t += temp;
                        break;
                    }
                }
                old_key = i;
            }*/
            //got the p_t with the key 
            //now complete the key with the p_t
           
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] vegenere = fill_vigenere(26);
            if (plainText.Length > key.Length)
            {
                int required_size = plainText.Length - key.Length ;
                for (int i = 0; i < required_size; i++)
                    key+=plainText[i];
            }
            string keystream = key.ToLower();
            string answer= "";
            for ( int i=0;i<keystream.Length;i++)
            {
                int row = plainText[i] - 97;
                int column = keystream[i] - 97;
                char temp = vegenere[row, column];
                answer += temp;

            }

            return answer;
        }
    }
}
