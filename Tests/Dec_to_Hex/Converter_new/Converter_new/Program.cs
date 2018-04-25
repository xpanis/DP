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
            int[] array_of_ints = new int[] {181, 95, 226, 188, 180, 13, 186, 93, 242, 88, 25, 253, 45, 42, 2, 185, 189, 62};
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
