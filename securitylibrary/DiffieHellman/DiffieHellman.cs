using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            double public_a = ModPow(alpha, xa,q);
            double public_b = ModPow(alpha, xb,q);
            double hash1 = Math.Pow(public_b, xa);
            double secret1 = ModPow((int)public_b, xa,q);
            double secret2 = ModPow((int)public_a, xb,q);
            List<int> outpout = new List<int>();
            outpout.Add((int)secret1);
            outpout.Add((int)secret2);

            return outpout;
        }
        static int ModPow(int b, int e, int m)
        {
            int result = 1;
            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    result = (result * b) % m;
                }
                b = (b * b) % m;
                e >>= 1;
            }
            return result;
        }
    }
}
