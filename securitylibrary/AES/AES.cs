using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{

    public class AES : CryptographicTechnique
    {
        public int numberRounds = 10;
        public int number_of_words = 4;
        public int number_of_bytes = 4;
        public static Byte[,] sbox = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };
        public static Byte[,] inv_sbox = {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        public override string Decrypt(string cipherText, string key)
        {
            int numberKeys = number_of_words * (numberRounds + 1);
            List<List<byte>> w = createMtrx(number_of_bytes, numberKeys);
            List<List<byte>> roundKey = createMtrx(number_of_bytes, number_of_words);
            List<List<byte>> state = mtrxPrep(cipherText);

            keySchedule(mtrxPrep(key), ref w);

            GetRoundKey(numberRounds, w, ref roundKey);
            AddRoundKey(ref state, roundKey);
           
            for (int i = numberRounds - 1; i >= 0; i--)
            {
                if (i == 0)
                {
                    InvShiftRows(ref state);
                    InvSubBytes(ref state);
                    GetRoundKey(0, w, ref roundKey);
                    AddRoundKey(ref state, roundKey);
                }
                else
                {
                    InvShiftRows(ref state);
                    InvSubBytes(ref state);
                    GetRoundKey(i, w, ref roundKey);
                    AddRoundKey(ref state, roundKey);
                    InvMixColumns(ref state);
                }
            }

            return ToHex(state);
        }

        public override string Encrypt(string plainText, string key)
        {
            int numberKeys = number_of_words * (numberRounds + 1);
            List<List<byte>> w = createMtrx(number_of_bytes, numberKeys);
            List<List<byte>> roundKey = createMtrx(number_of_bytes, number_of_words);
            List<List<byte>> state = mtrxPrep(plainText);

            keySchedule(mtrxPrep(key), ref w);


            for (int i = 0; i <= numberRounds; i++)
            {
                if(i==0)
                {
                    GetRoundKey(0, w, ref roundKey);
                    AddRoundKey(ref state, roundKey);
                }
                else if(i==numberRounds)
                {
                    SubBytes(ref state);
                    ShiftRows(ref state);
                    GetRoundKey(numberRounds, w, ref roundKey);
                    AddRoundKey(ref state, roundKey);
                }
                else
                {
                    SubBytes(ref state);
                    ShiftRows(ref state);
                    MixColumns(ref state);
                    GetRoundKey(i, w, ref roundKey);
                    AddRoundKey(ref state, roundKey);
                }
            }

            return ToHex(state);
        }

        public List<List<Byte>> createMtrx(int row, int col)
        {
            List<List<byte>> value = new List<List<byte>>();
            for (int i = 0; i < row; i++)
            {
                List<byte> innerList = new List<byte>();
                for (int j = 0; j < col; j++)
                {
                    innerList.Add(0x00);
                }
                value.Add(innerList);
            }
            return value;
        }

        // XD
        public void GetRoundKey(int round, List<List<Byte>> w, ref List<List<Byte>> key)
        {
            int indx = round * number_of_words; 
            for (int i = 0; i < number_of_words; i++)
                for (int j = 0; j < number_of_bytes; j++)
                    key[j][i] = w[j][indx + i];
        }


        public string ToHex(List<List<Byte>> state)
        {
            StringBuilder hexaStr = new StringBuilder("0x");
            for (int i = 0; i < number_of_words; i++)
            {
                for (int j = 0; j < number_of_bytes; j++)
                {
                    string value = state[j][i].ToString("X2");
                    hexaStr.Append(value);
                }
            }
            return hexaStr.ToString();
        }

        //XD
        public List<List<byte>> mtrxPrep(string hexTxt)
        {
            List<List<byte>> state = new List<List<byte>>();
            List<List<byte>> temp = new List<List<byte>>();
            
            int j = 2; 
            for (int i = 0; i < number_of_words; i++)
            {
                List<byte> row = new List<byte>();

                for (int k = 0; k < number_of_bytes; k++)
                {
                    string hexByte = hexTxt.Substring(j, 2);
                    byte byteValue = byte.Parse(hexByte, System.Globalization.NumberStyles.HexNumber);
                    row.Add(byteValue);
                    j += 2;
                }

                temp.Add(row);
            }

            for (int i = 0; i < number_of_bytes; i++)
            {
                List<byte> row = new List<byte>();
                for (int k = 0; k < number_of_words; k++)
                {
                    row.Add(temp[k][i]);
                }
                state.Add(row);
            }
            return state;
        }

        public void AddRoundKey(ref List<List<Byte>> state, List<List<Byte>> key)
        {
            for (int i = 0; i < number_of_words; i++)
                for (int j = 0; j < number_of_bytes; j++)
                    state[j][i] = (Byte)(state[j][i] ^ key[j][i]);
        }

        public void SubBytes(ref List<List<Byte>> state)
        {
            for (int i = 0; i < number_of_words; i++)
                for (int j = 0; j < number_of_bytes; j++)
                    state[j][i] = sbox[state[j][i] / 16, state[j][i] % 16];
        }

        public void InvSubBytes(ref List<List<Byte>> state)
        {
            for (int i = 0; i < number_of_words; i++)
                for (int j = 0; j < number_of_bytes; j++)
                    state[j][i] = inv_sbox[state[j][i] / 16, state[j][i] % 16];
        }

        public void ShiftRow(ref List<List<Byte>> state, int row, int step)
        {
            for (int i = 0; i < step; i++)
            {
                Byte temp = state[row][0];
                for (int j = 0; j < number_of_words - 1; j++)
                {
                    state[row][j] = state[row][j + 1];
                }
                state[row][number_of_words - 1] = temp;
            }
        }

        public void ShiftRows(ref List<List<Byte>> state)
        {
            ShiftRow(ref state, 1, 1);
            ShiftRow(ref state, 2, 2);
            ShiftRow(ref state, 3, 3);
        }

        public void InvShiftRows(ref List<List<Byte>> state)
        {
            ShiftRow(ref state, 1, 3);
            ShiftRow(ref state, 2, 2);
            ShiftRow(ref state, 3, 1);
        }

        public void MixColumns(ref List<List<Byte>> state)
        {
            List<byte> a = new List<byte>(new byte[number_of_bytes]);
            List<byte> b = new List<byte>(new byte[number_of_bytes]);

            for (int col = 0; col < number_of_words; col++)
            {
                for (int row = 0; row < number_of_bytes; row++)
                {
                    a[row] = state[row][col];
                }

                b[0] = (byte)(MulBytes(0x02, a[0]) ^ MulBytes(0x03, a[1]) ^ a[2] ^ a[3]);
                b[1] = (byte)(MulBytes(0x02, a[1]) ^ MulBytes(0x03, a[2]) ^ a[3] ^ a[0]);
                b[2] = (byte)(MulBytes(0x02, a[2]) ^ MulBytes(0x03, a[3]) ^ a[0] ^ a[1]);
                b[3] = (byte)(MulBytes(0x02, a[3]) ^ MulBytes(0x03, a[0]) ^ a[1] ^ a[2]);

                for (int row = 0; row < number_of_bytes; row++)
                {
                    state[row][col] = b[row];
                }
            }
        }

        public void InvMixColumns(ref List<List<Byte>> state)
        {
            for (int col = 0; col < number_of_words; col++)
            {
                byte[] a = new byte[number_of_bytes];
                byte[] b = new byte[number_of_bytes];

                for (int row = 0; row < number_of_bytes; row++)
                {
                    a[row] = state[row][col];
                }
                b[0] = (byte)(MulBytes(0x0E, a[0]) ^ MulBytes(0x0B, a[1]) ^ MulBytes(0x0D, a[2]) ^ MulBytes(0x09, a[3]));
                b[1] = (byte)(MulBytes(0x09, a[0]) ^ MulBytes(0x0E, a[1]) ^ MulBytes(0x0B, a[2]) ^ MulBytes(0x0D, a[3]));
                b[2] = (byte)(MulBytes(0x0D, a[0]) ^ MulBytes(0x09, a[1]) ^ MulBytes(0x0E, a[2]) ^ MulBytes(0x0B, a[3]));
                b[3] = (byte)(MulBytes(0x0B, a[0]) ^ MulBytes(0x0D, a[1]) ^ MulBytes(0x09, a[2]) ^ MulBytes(0x0E, a[3]));

                for (int row = 0; row < number_of_bytes; row++)
                {
                    state[row][col] = b[row];
                }
            }
        }

        public void keySchedule(List<List<Byte>> key, ref List<List<Byte>> word)
        {
            List<byte> current = Enumerable.Repeat((byte)0x00, number_of_bytes).ToList(); ;
            List<byte> rcon = Enumerable.Repeat((byte)0x00, number_of_bytes).ToList(); ;

            for (int i = 0; i < number_of_words; i++)
            {
                for (int j = 0; j < number_of_bytes; j++)
                {
                    word[j][i] = key[j][i];
                }
            }

            int numberKeys = number_of_words * (numberRounds + 1);

            for (int i = number_of_words; i < numberKeys; i++)
            {
                for (int j = 0; j < number_of_bytes; j++)
                {
                    current[j] = word[j][i - 1];
                }

                if (i % number_of_words == 0)
                {
                    RotWord(ref current);
                    SubWord(ref current);
                    Rcon(ref rcon, i / number_of_words);
                    XorWords(current, rcon, ref current);
                }

                for (int j = 0; j < number_of_bytes; j++)
                {
                    word[j][i] = (byte)(word[j][i - number_of_words] ^ current[j]);
                }
            }
        }

        public Byte MulBytes(Byte b1, Byte b2)
        {
            byte ans = 0;
            byte temp;

            for (int i = 0; i < 8; i++)
            {
                if ((b2 & 0x01) == 0x01)
                {
                    temp = b1;
                    for (int j = 0; j < i; j++)
                    {
                        byte highBit = (byte)(temp & 0x80);
                        temp = (byte)(temp << 1);
                        if (highBit > 0x00)
                        {
                            temp = (byte)(temp ^ 0x1B);
                        }
                    }
                    ans ^= temp;
                }
                b2 = (byte)(b2 >> 1);
            }

            return ans;
        }

        public void RotWord(ref List<Byte> word)
        {
            Byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        public void SubWord(ref List<Byte> word)
        {
            for (int i = 0; i < 4; i++)
            {
                word[i] = sbox[word[i] / 16, word[i] % 16];
            }
        }

        public void XorWords(List<Byte> x, List<Byte> y, ref List<Byte> z)
        {
 
            for (int i = 0; i < 4; i++)
            {
                z[i] = (Byte)(x[i] ^ y[i]);
            }
        }

        public void Rcon(ref List<Byte> word, int n)
        {
            Byte[] rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
            word[0] = rcon[n-1];
            word[1] = word[2] = word[3] = 0x00;
        }
    }
}
