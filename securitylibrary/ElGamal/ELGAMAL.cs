using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // Calculate C1 and C2 
            long C1 = Modwithpower(alpha, k, q);
            long C2 = (m * Modwithpower(y, k, q)) % q;

            return new List<long> { C1, C2 };
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            // Calculate the decryption exponent d 
            long d = Modwithpower(c1, q - 1 - x, q);

            // plaintext by dividing C2 by d modulus q
            int m = (int)((c2 * d) % q);

            return m;
        }

        private long Modwithpower(long baseV, long exp, long modulus)
        {
           
            if (modulus == 1)
                return 0;

            long c = 1;
            baseV %=  modulus;
            while (exp > 0)
            {
                if (exp % 2 == 1)
                {
                    c = (c * baseV) % modulus;
                }
                exp /= 2;
                baseV = (baseV * baseV) % modulus;
            }

            return c;
        }
    }
}
