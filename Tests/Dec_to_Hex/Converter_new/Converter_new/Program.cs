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
            int[] array_of_ints = new int[] {43, 205, 234, 100, 116, 3, 88, 8, 12, 72, 244, 28, 75, 94, 99, 152, 110, 102};
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
