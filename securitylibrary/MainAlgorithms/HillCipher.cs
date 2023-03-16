using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int matrix_size = 2;
            int number_of_sub_plain = plainText.Count() / matrix_size;
            List<List<int>> plaintextcutt = new List<List<int>>();
            List<int> result = new List<int>();
            int counter = 0;
            for (int i = 0; i < number_of_sub_plain; i++)
            {
                List<int> temp = new List<int>();
                plaintextcutt.Add(temp);
                for (int j = 0; j < matrix_size; j++)
                {
                    plaintextcutt[i].Add(plainText[counter]);
                    counter++;
                }
            }
            int[,] key_matrix = new int[2, 2];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            key_matrix[0, 0] = i;
                            key_matrix[1, 0] = j;
                            key_matrix[0, 1] = k;
                            key_matrix[1, 1] = l;
                            for (int s = 0; s < number_of_sub_plain; s++)
                            {
                                int sum1 = 0;
                                int sum2 = 0;
                                sum1 = plaintextcutt[s][0] * key_matrix[0, 0] + plaintextcutt[s][1] * key_matrix[1, 0];
                                sum2 = plaintextcutt[s][0] * key_matrix[0, 1] + plaintextcutt[s][1] * key_matrix[1, 1];
                                result.Add((int)(sum1 % 26));
                                result.Add((int)(sum2 % 26));
                            }
                            bool check = true;
                            for (int q = 0; q < 4; q++)
                            {
                                if (result[q] != cipherText[q])
                                {
                                    check = false;
                                }
                            }
                            if (check)
                            {
                                List<int> argt = new List<int>();
                                for (int p = 0; p < 2; p++)
                                {
                                    for (int aa = 0; aa < 2; aa++)
                                    {
                                        argt.Add(key_matrix[aa, p]);
                                    }
                                }
                                return argt;
                            }
                            else
                            {
                                result.Clear();
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int key_number = key.Count();
            for (int i = 0; i < key_number; i++)
            {
                if (key[i] > 26 || key[i] < 0)
                    throw new Exception();
            }
            int matrix_size = (int)Math.Sqrt(key_number);
            double[,] key_matrix = new double[matrix_size, matrix_size];

            int matrix_index = 0;
            for (int i = 0; i < matrix_size; i++)
            {
                for (int j = 0; j < matrix_size; j++)
                {
                    key_matrix[j, i] = key[matrix_index];
                    matrix_index++;
                }
            }
            double[,] inverse_key = InverseMatrix(key_matrix);
            int number_of_sub_plain = cipherText.Count() / matrix_size;
            List<List<double>> ciphertextcutt = new List<List<double>>();
            List<int> result = new List<int>();
            int counter = 0;
            for (int i = 0; i < number_of_sub_plain; i++)
            {
                List<double> temp = new List<double>();
                ciphertextcutt.Add(temp);
                for (int j = 0; j < matrix_size; j++)
                {
                    ciphertextcutt[i].Add(cipherText[counter]);
                    counter++;
                }
            }
            for (int i = 0; i < number_of_sub_plain; i++)
            {
                for (int j = 0; j < matrix_size; j++)
                {
                    double sum = 0;
                    for (int k = 0; k < matrix_size; k++)
                    {
                        sum += ciphertextcutt[i][k] * inverse_key[k, j];
                    }
                    bool flag = true;
                    while (flag)
                    {
                        if (sum < 0)
                        {
                            sum += 26;
                        }
                        else
                        {
                            flag = false;
                        }
                    }
                    result.Add((int)(sum % 26));
                }
            }
            return result;

            double[,] InverseMatrix(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double[,] inverse = new double[n, n];

                if (n == 1)
                {
                    inverse[0, 0] = 1 / matrix[0, 0];
                    return inverse;
                }
                else if (n == 2)
                {
                    double det = matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
                    if (det == 0)
                    {
                        throw new Exception();
                    }
                    double c = gcd((int)det, 26);
                    if (gcd((int)det, 26) != 1 && gcd((int)det, 26) != -1)
                    {
                        throw new Exception();
                    }
                    inverse[0, 0] = matrix[1, 1] / det;
                    inverse[0, 1] = -matrix[0, 1] / det;
                    inverse[1, 0] = -matrix[1, 0] / det;
                    inverse[1, 1] = matrix[0, 0] / det;
                    return inverse;
                }
                else
                {
                    double det = Determinant(matrix);
                    if (det == 0)
                    {
                        throw new Exception();
                    }
                    if (gcd((int)det, 26) != 1 && gcd((int)det, 26) != -1)
                    {
                        throw new Exception();
                    }
                    for (int i = 2; i < 26; i++)
                    {
                        if ((det * i) % 26 == 1)
                        {
                            det = i;
                            break;
                        }
                    }
                    double[,] adjugate = Adjugate(matrix);
                    for (int i = 0; i < n; i++)
                    {
                        for (int j = 0; j < n; j++)
                        {
                            inverse[i, j] = (adjugate[i, j] * det) % 26;
                        }
                    }
                    return inverse;
                }
            }

            double Determinant(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double det = 0;
                if (n == 1)
                {
                    det = matrix[0, 0];
                }
                else if (n == 2)
                {
                    det = matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
                }
                else
                {
                    for (int i = 0; i < n; i++)
                    {
                        double[,] submatrix = new double[n - 1, n - 1];
                        for (int j = 1; j < n; j++)
                        {
                            for (int k = 0; k < n; k++)
                            {
                                if (k < i)
                                {
                                    submatrix[j - 1, k] = matrix[j, k];
                                }
                                else if (k > i)
                                {
                                    submatrix[j - 1, k - 1] = matrix[j, k];
                                }
                            }
                        }
                        double cofactor = Math.Pow(-1, i) * Determinant(submatrix);
                        det += matrix[0, i] * cofactor;
                    }
                }

                return det % 26;
            }

            double gcd(int num1, int num2)
            {
                if (num1 < num2)
                {
                    int temp = num1;
                    num1 = num2;
                    num2 = temp;
                }

                int remainder = num1 % num2;

                while (remainder != 0)
                {
                    num1 = num2;
                    num2 = remainder;
                    remainder = num1 % num2;
                }
                int gccd = num2;
                return gccd;
            }

            double[,] Adjugate(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double[,] adjugate = new double[n, n];
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        double[,] submatrix = new double[n - 1, n - 1];
                        for (int k = 0; k < n; k++)
                        {
                            for (int l = 0; l < n; l++)
                            {
                                if (k < i && l < j)
                                {
                                    submatrix[k, l] = matrix[k, l];
                                }
                                else if (k < i && l > j)
                                {
                                    submatrix[k, l - 1] = matrix[k, l];
                                }
                                else if (k > i && l < j)
                                {
                                    submatrix[k - 1, l] = matrix[k, l];
                                }
                                else if (k > i && l > j)
                                {
                                    submatrix[k - 1, l - 1] = matrix[k, l];
                                }
                            }
                        }
                        double cofactor = Math.Pow(-1, i + j) * Determinant(submatrix);
                        adjugate[j, i] = cofactor;
                    }
                }
                return adjugate;
            }
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int key_number = key.Count();
            int matrix_size = (int)Math.Sqrt(key_number);

            int[,] key_matrix = new int[matrix_size, matrix_size];

            // add 'X' to align the plain text

            if (plainText.Count() % matrix_size != 0)
            {
                int paddingLength = (matrix_size - plainText.Count() % matrix_size) % matrix_size;
                for (int i = 0; i < paddingLength; i++)
                {
                    plainText.Add(23);
                }
            }

            // converting the list to a square matrix

            int matrix_index = 0;
            for (int i = 0; i < matrix_size; i++)
            {
                for (int j = 0; j < matrix_size; j++)
                {
                    key_matrix[j, i] = key[matrix_index];
                    matrix_index++;
                }
            }
            int number_of_sub_plain = plainText.Count() / matrix_size;
            List<List<int>> plaintextcutt = new List<List<int>>();
            List<int> result = new List<int>();
            int counter = 0;
            for (int i = 0; i < number_of_sub_plain; i++)
            {
                List<int> temp = new List<int>();
                plaintextcutt.Add(temp);
                for (int j = 0; j < matrix_size; j++)
                {
                    plaintextcutt[i].Add(plainText[counter]);
                    counter++;
                }
            }
            for (int i = 0; i < number_of_sub_plain; i++)
            {
                for (int j = 0; j < matrix_size; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < matrix_size; k++)
                    {
                        sum += plaintextcutt[i][k] * key_matrix[k, j];
                    }
                    result.Add((sum % 26));
                }
            }
            return result;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int[,] key_matrix = new int[3, 3];
            double[,] plain_matrix = new double[3, 3];
            double[,] cipher_matrix = new double[3, 3];

            int matrix_index = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    cipher_matrix[j, i] = cipherText[matrix_index];
                    plain_matrix[j, i] = plainText[matrix_index];
                    matrix_index++;
                }
            }
            double[,] invrse_plain = InverseMatrix(plain_matrix);

            List<int> result = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        sum += (int)((invrse_plain[k, j]) * cipher_matrix[i, k]);
                    }
                    bool flag = true;
                    while (flag)
                    {
                        if (sum < 0)
                        {
                            sum = sum + 26;
                        }
                        else
                        {
                            flag = false;
                        }

                    }
                    result.Add(sum % 26);
                }
            }

            return result;
            double[,] InverseMatrix(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double[,] inverse = new double[n, n];

                if (n == 1)
                {
                    inverse[0, 0] = 1 / matrix[0, 0];
                    return inverse;
                }
                else if (n == 2)
                {
                    double det = matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
                    if (det == 0)
                    {
                        throw new Exception("Matrix is singular and has no inverse.");
                    }
                    inverse[0, 0] = matrix[1, 1] / det;
                    inverse[0, 1] = -matrix[0, 1] / det;
                    inverse[1, 0] = -matrix[1, 0] / det;
                    inverse[1, 1] = matrix[0, 0] / det;
                    return inverse;
                }
                else
                {
                    double det = Determinant(matrix);
                    if (det == 0)
                    {
                        throw new Exception("Matrix is singular and has no inverse.");
                    }
                    for (int i = 2; i < 26; i++)
                    {
                        if ((det * i) % 26 == 1)
                        {
                            det = i;
                            break;
                        }
                    }
                    double[,] adjugate = Adjugate(matrix);
                    for (int i = 0; i < n; i++)
                    {
                        for (int j = 0; j < n; j++)
                        {
                            inverse[i, j] = (adjugate[i, j] * det) % 26;
                        }
                    }
                    return inverse;
                }
            }

            double Determinant(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double det = 0;
                if (n == 1)
                {
                    det = matrix[0, 0];
                }
                else if (n == 2)
                {
                    det = matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
                }
                else
                {
                    for (int i = 0; i < n; i++)
                    {
                        double[,] submatrix = new double[n - 1, n - 1];
                        for (int j = 1; j < n; j++)
                        {
                            for (int k = 0; k < n; k++)
                            {
                                if (k < i)
                                {
                                    submatrix[j - 1, k] = matrix[j, k];
                                }
                                else if (k > i)
                                {
                                    submatrix[j - 1, k - 1] = matrix[j, k];
                                }
                            }
                        }
                        double cofactor = Math.Pow(-1, i) * Determinant(submatrix);
                        det += matrix[0, i] * cofactor;
                    }
                }

                return det % 26;
            }

            double[,] Adjugate(double[,] matrix)
            {
                int n = matrix.GetLength(0);
                double[,] adjugate = new double[n, n];
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        double[,] submatrix = new double[n - 1, n - 1];
                        for (int k = 0; k < n; k++)
                        {
                            for (int l = 0; l < n; l++)
                            {
                                if (k < i && l < j)
                                {
                                    submatrix[k, l] = matrix[k, l];
                                }
                                else if (k < i && l > j)
                                {
                                    submatrix[k, l - 1] = matrix[k, l];
                                }
                                else if (k > i && l < j)
                                {
                                    submatrix[k - 1, l] = matrix[k, l];
                                }
                                else if (k > i && l > j)
                                {
                                    submatrix[k - 1, l - 1] = matrix[k, l];
                                }
                            }
                        }
                        double cofactor = Math.Pow(-1, i + j) * Determinant(submatrix);
                        adjugate[j, i] = cofactor;
                    }
                }
                return adjugate;
            }
            throw new InvalidAnlysisException();
        }

    }
}
