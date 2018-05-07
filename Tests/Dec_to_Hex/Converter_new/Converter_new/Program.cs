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
            int[] array_of_ints = new int[] {149, 62, 8, 75, 30, 50, 26, 17, 168, 101, 38, 192, 121, 52, 244, 93, 237, 122};
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
