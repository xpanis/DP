using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Converter_new
{
    class Program
    {
        static void Main(string[] args)
        {
            int[] array_of_ints = new int[] {150, 121, 226, 86, 198, 58, 145, 107, 135, 237, 61, 243, 22, 240, 85, 172, 253, 11};
            string[] array_of_hex = new string[array_of_ints.Length];
            for(int i = 0; i < array_of_ints.Length; i++)
            {
                array_of_hex[i] = array_of_ints[i].ToString("X");
            }

            Console.WriteLine("Pole Hexa je: ");
            for (int i = 0; i < array_of_ints.Length; i++)
            {
                Console.Write(array_of_hex[i] + " ");
            }
            
        }
    }
}
