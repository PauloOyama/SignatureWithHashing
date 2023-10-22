using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;

class LamportVerifier {
    
    private HashAlgorithm HashFunc;
    public List<(byte[], byte[])> publicKey = new List<(byte[], byte[])>();
    // public BigInteger[] signMessage = new BigInteger[];

        public LamportVerifier(HashAlgorithm HashFunc)
    {
        this.HashFunc = HashFunc;
    }


    static void Main(){

        SHA256 hashFunc = SHA256.Create();
        LamportVerifier verifier = new LamportVerifier(hashFunc);
        using (StreamReader reader = new StreamReader(@"./message.txt")){
            byte[] publicKey1 = new byte[32];
            byte[] publicKey2 = new byte[32];
            byte[] verify = new byte[32];
            BigInteger[] num = new BigInteger[256]; 
            for (int i = 0; i < 3; i++){
                string line = reader.ReadLine()!;
                if(i%3 == 0){
                    publicKey1 = Encoding.Unicode.GetBytes(line!);
                    Console.WriteLine("PK_0"); 
                    PrintByteArray(publicKey1);
                }else if(i%3==1){
                    publicKey2 = Encoding.Unicode.GetBytes(line!);
                    Console.WriteLine("PK_1"); 
                    PrintByteArray(publicKey2);
                }else{
                    Console.WriteLine("Signature"); 
                    Console.WriteLine(Encoding.Unicode.GetBytes(line!).Length);
                    PrintByteArray(Encoding.Unicode.GetBytes(line!));
                    verify = hashFunc.ComputeHash(Encoding.Unicode.GetBytes(line!));
                    Console.WriteLine("Hash Signature"); 
                    Console.WriteLine(Encoding.Unicode.GetBytes(line!).Length);
                    PrintByteArray(verify);
                    
                    // BigInteger number = new BigInteger(line);
                    // Console.WriteLine(number);
                    Console.WriteLine(publicKey1.SequenceEqual(verify));
                    Console.WriteLine(publicKey2.SequenceEqual(verify));
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