using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            char a= cipherText.ElementAt(1);
            int x = 2;
            plainText = plainText.ToUpper();
            for(int i = 2; i < plainText.Length; i++)
            {
                if (plainText.ElementAt(i).Equals(a))
                    break;
                else
                    x++;
            }

            return x;
        }

        public string Decrypt(string cipherText, int key)
        {

            // calculate the number of rows needed
            int cols = cipherText.Length / key;
            if (cipherText.Length % key != 0)
            {
                cols += 1;
            }
            
            // create the grid
            char[,] grid = new char[cols, key];

            // fill in the grid with the ciphertext in the original order
            int index = 0;
            for (int j = 0; j < key; j++)
            {
                for (int i = 0; i < cols ; i++)
                {
                    if (index < cipherText.Length)
                    {
                        grid[i, j] = cipherText[index];
                        index++;
                    }
                }
            }

            // read the message row by row
            string plainText = "";
            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += grid[i, j];
                }
            }
            Console.WriteLine(plainText);
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {

            // calculate the number of rows needed
            int rows = plainText.Length / key;
            if (plainText.Length % key != 0)
            {
                rows += 1;
            }

            // create the grid
            char[,] grid = new char[rows, key];

            // fill in the grid with the message
            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (index < plainText.Length)
                    {
                        grid[i, j] = plainText[index];
                        index++;
                    }
                }
            }

            // read the message column by column in the new order
            string cipherText = "";
            for (int j = 0; j < key; j++)
            {
                for (int i = 0; i < rows; i++)
                {
                    cipherText += grid[i, j];
                }
            }
            Console.WriteLine(cipherText);
            return cipherText;
        }
    }
}

