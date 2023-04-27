using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Mod_pow(int Base,int Pow,int Mod)
        {
            int n = 1;
            for (int i=1;i<=Pow;i++)
            {
                n = (n * Base)%Mod;
            }
            return n;
        }
        public int extended_euc(int n,int Base)
        {
            int m = Base;
            int a1 = 1;
            int a2 = 0;
            int b1 =0;
            int b2 = 1;
            
            while(n!=0 &&n !=1)
            {
                int q =  Base/ n;
                int t1 = a1 - (q * b1);
                int t2 = a2 - (q * b2);
                int t3 = Base - (q * n);
                a1 = b1;
                a2 = b2;
                Base = n;
                b1 = t1;
                b2 = t2;
                n = t3;

            }
            if (n == 1)
            {
                if (b2 < -1)
                    return b2 + m;
                else
                    return b2;
            }
            return -1;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return Mod_pow(M, e, n);

            /*        BigInteger p_new = BigInteger.Parse(p.ToString());
                    BigInteger q_new = BigInteger.Parse(q.ToString());
                    BigInteger M_new = BigInteger.Parse(M.ToString());
                    BigInteger e_new = BigInteger.Parse(e.ToString());
                    BigInteger res = BigInteger.ModPow(M_new, e_new, (p * q));
                    return int.Parse(res.ToString());*/
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //D =C ^ d % n got C and n = p*q we want d  
            // d = e^-1 mod euler  
            int euler = (p - 1) * (q - 1);
            int d = extended_euc(e, euler);
            return Mod_pow(C, d, p*q);
        }
    }
}   