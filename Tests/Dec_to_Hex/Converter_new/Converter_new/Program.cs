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
            int[] array_of_ints = new int[] {2, 54, 212, 88, 43, 231, 140, 3, 238, 65, 84, 124, 146, 16, 230, 224, 239, 71, 84, 211, 231, 20, 144, 254, 74, 67, 88, 196, 143, 70, 43, 185, 155, 160};
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
