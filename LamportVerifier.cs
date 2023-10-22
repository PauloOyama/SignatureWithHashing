using System.Text;
using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class LamportVerifier {
    public List<(byte[], byte[])> publicKey = new List<(byte[], byte[])>();
    // public BigInteger[] signMessage = new BigInteger[];

    static void Main(){

        using (StreamReader reader = new StreamReader(@"./message.txt")){
            byte[] publicKey1 = new byte[32];
            byte[] publicKey2 = new byte[32];
            BigInteger[] num = new BigInteger[256]; 
            for (int i = 0; i < 3; i++){
                string line = reader.ReadLine();
                if(i%3 == 0){
                    publicKey1 = Encoding.Unicode.GetBytes(line);
                    PrintByteArray(publicKey1);
                }else if(i%3==1){
                    publicKey2 = Encoding.Unicode.GetBytes(line); 
                    PrintByteArray(publicKey2);
                }else{
                    Console.WriteLine(line);
                    // BigInteger number = new BigInteger(line);
                    // Console.WriteLine(number);
                }
            }  
        }

    }

    public static void PrintByteArray(byte[] array)
    {
        for (int i = 0; i < array.Length; i++)
        {
            Console.Write($"{array[i]:X2}");
            if ((i % 4) == 3) Console.Write(" ");
        }
        Console.WriteLine();
    }
}