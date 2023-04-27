using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //intialize
            List<int> X = new List<int>() { -1, 1, 0, baseN, };

            List<int> Y = new List<int>() { -1, 0, 1, number };

            while (true)
            {
                switch (Y[3])
                {   //GCD NOT FOUND
                    case 0:
                        return -1;

                    case 1:
                        return ((Y[2] % baseN) + baseN) % baseN;
                }


                int Q = X[3] / Y[3];

                //temp of swapping 
                List<int> T = new List<int>() { -1, 0, 0, 0 };

                //swapping 
                T[1] = X[1] - (Q * Y[1]);
                T[2] = X[2] - (Q * Y[2]);
                T[3] = X[3] - (Q * Y[3]);

                X[1] = Y[1];
                X[2] = Y[2];
                X[3] = Y[3];

                Y[1] = T[1];
                Y[2] = T[2];
                Y[3] = T[3];
            }
        }
    }
}
