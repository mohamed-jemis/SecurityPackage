using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
  
        public string Analyse(string plainText, string cipherText)
        {

            // Create a dictionary to store the mappings
            var mappings = new Dictionary<char, char>();
            string alpha = "abcdefghijklmnopqrstuvwxyz";


            // Loop through the characters in plainText and add the corresponding
            // character in cipherText to the mappings dictionary
            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = char.ToLower(plainText[i]);
                char cipherChar = char.ToLower(cipherText[i]);

                // Skip spaces and characters that are already in the mappings dictionary
                if (plainChar == ' ' || mappings.ContainsKey(plainChar))
                {
                    continue;
                }

                // Add the mapping to the dictionary
                mappings.Add(plainChar, cipherChar);
            }

            // Check if all letters are mapped
            if (mappings.Count < 26)
            {
  
                // Loop through the alphabet and add any missing letters to the mappings dictionary
                foreach (char letter in alpha)
                {
                    if (!mappings.ContainsKey(letter))
                    {
                        // Find a letter in the alphabet that is not already in the mappings dictionary
                        char unusedLetter = alpha.FirstOrDefault(l => !mappings.ContainsValue(l));

                        // Add the mapping to the dictionary
                        mappings.Add(letter, unusedLetter);
                    }
                }
            }

            // Check if the key contains all 26 letters
            if (mappings.Count != 26)
            {
                return "";
            }

            // Create the key by looping through the alphabet and using the mappings dictionary
            string key = "";
            foreach (char letter in alpha)
            {
                if (mappings.ContainsKey(letter))
                {
                    key += mappings[letter];
                }
                else
                {
                    return "";
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // Create a dictionary to map the key letters to the plaintext letters
            var mappings = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                mappings[key[i]] = (char)('a' + i);
            }

            // Apply the mappings to the ciphertext to create the plaintext
            var plaintext = new StringBuilder();
            foreach (var letter in cipherText)
            {
                if (char.IsLetter(letter))
                {
                    plaintext.Append(mappings[char.ToLower(letter)]);
                }
                else
                {
                    plaintext.Append(letter);
                }
            }

            return plaintext.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            // Create a dictionary to map the plaintext letters to the key letters
            var mappings = new Dictionary<char, char>();
            for (int i = 0; i < key.Length; i++)
            {
                mappings[(char)('a' + i)] = key[i];
            }

            // Apply the mappings to the plaintext to create the ciphertext
            var ciphertext = new StringBuilder();
            foreach (var letter in plainText)
            {
                if (char.IsLetter(letter))
                {
                    ciphertext.Append(mappings[char.ToLower(letter)]);
                }
                else
                {
                    ciphertext.Append(letter);
                }
            }

            return ciphertext.ToString();
        }





        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // Define the expected character frequencies in descending order
            var expectedFrequencies = new Dictionary<char, double>
            {
                ['e'] = 12.51,
                ['t'] = 9.25,
                ['a'] = 8.04,
                ['o'] = 7.60,
                ['i'] = 7.26,
                ['n'] = 7.09,
                ['s'] = 6.54,
                ['r'] = 6.12,
                ['h'] = 5.49,
                ['l'] = 4.14,
                ['d'] = 3.99,
                ['c'] = 3.06,
                ['u'] = 2.71,
                ['m'] = 2.53,
                ['f'] = 2.30,
                ['p'] = 2.00,
                ['g'] = 1.96,
                ['w'] = 1.92,
                ['y'] = 1.73,
                ['b'] = 1.54,
                ['v'] = 0.99,
                ['k'] = 0.67,
                ['x'] = 0.19,
                ['j'] = 0.16,
                ['q'] = 0.11,
                ['z'] = 0.09
            };

            // Count the actual character frequencies in the ciphertext
            var actualFrequencies = new Dictionary<char, int>();
            foreach (var c in cipher.ToLower())
            {
                if (char.IsLetter(c))
                {
                    if (actualFrequencies.ContainsKey(c))
                    {
                        actualFrequencies[c]++;
                    }
                    else
                    {
                        actualFrequencies[c] = 1;
                    }
                }
            }

            // Calculate the frequency ratio of each character in the ciphertext
            var actualRatios = new Dictionary<char, double>();
            var totalCount = actualFrequencies.Values.Sum();
            foreach (var kvp in actualFrequencies)
            {
                actualRatios[kvp.Key] = 100.0 * kvp.Value / totalCount;
            }

            // Sort the characters in descending order of their frequency ratios
            var sortedActualRatios = actualRatios.OrderByDescending(kvp => kvp.Value).ToList();

            // Create a mapping of each character in the ciphertext to the corresponding character in the plaintext
            var mapping = new Dictionary<char, char>();
            for (int i = 0; i < sortedActualRatios.Count; i++)
            {
                var ciphertextChar = sortedActualRatios[i].Key;
                var plaintextChar = expectedFrequencies.ElementAt(i).Key;
                mapping[ciphertextChar] = plaintextChar;
            }

            // Replace each character in the ciphertext with its corresponding character in the plaintext
            var plaintext = new StringBuilder();
            foreach (var c in cipher)
            {
                var plaintextChar = mapping.ContainsKey(char.ToLower(c)) ? mapping[char.ToLower(c)] : c;
                plaintext.Append(char.IsUpper(c) ? char.ToUpper(plaintextChar) : plaintextChar);
            }

            return plaintext.ToString();
        }
    }
}
