using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

    /// <summary>
    /// Class <c>LamportSigner</c> takes a message and using a tuple of public keys generate a 
    /// signed message.
    /// </summary>
class LamportSigner
{
    public List<(BigInteger zero, BigInteger one)> privateKey = new List<(BigInteger, BigInteger)>();
    public List<(byte[], byte[])> publicKey = new List<(byte[], byte[])>();
    private Random rnd = new Random();
    private HashAlgorithm HashFunc;

    public LamportSigner(HashAlgorithm HashFunc)
    {
        this.HashFunc = HashFunc;
    }

    // static void Main(){
    //     // string testString = "Hello World!";

    //     SHA256 hashFunc = SHA256.Create();
    //     // byte[] hashVal = hashFunc.ComputeHash(Encoding.Unicode.GetBytes(testString));

    //     // PrintByteArray(hashVal);
    //     LamportSigner signer = new LamportSigner(hashFunc);
    //     signer.Init();
    //     Console.WriteLine(signer.privateKey.Count);
    //     BigInteger[] sig = signer.Sign(Encoding.Unicode.GetBytes("Badabingus."));

    //     // Console.WriteLine(sig.Length);

    //     using (StreamWriter writer = new StreamWriter(@"./message.txt"))
    //     {
    //         for (int i = 0; i < 1; i++){
    //             writer.WriteLine(Encoding.Unicode.GetString(signer.publicKey[i].Item1));
    //             writer.WriteLine(Encoding.Unicode.GetString(signer.publicKey[i].Item2));
    //             writer.WriteLine(Encoding.Unicode.GetString(sig[i].ToByteArray()));
    //             if(i==0){
    //                 Console.WriteLine("PK_0");
    //                 PrintByteArray(signer.publicKey[i].Item1);
    //                 Console.WriteLine("PK_1");
    //                 PrintByteArray(signer.publicKey[i].Item2);
    //             }
    //         }
    //     }

    // }

    public void Init()
    {
        for (int i = 0; i < 256; i++)
        {
            var privTuple = (GenerateRandom256Bit(), GenerateRandom256Bit());
            privateKey.Add(privTuple);
            var pubTuple = (privTuple.Item1.ToByteArray(), privTuple.Item2.ToByteArray());
            pubTuple.Item1 = HashFunc.ComputeHash(pubTuple.Item1);
            pubTuple.Item2 = HashFunc.ComputeHash(pubTuple.Item2);
            publicKey.Add(pubTuple);
        }
    }


    /*
    00000001 = 0x01
    00000010 = 0x02
    00000100 = 0x04
    00001000 = 0x08
    00010000 = 0x10
    00100000 = 0x20
    01000000 = 0x40
    10000000 = 0x80
    */

    /// <summary>
    /// Class <c>Point</c> models a point in a two-dimensional plane.
    /// </summary>
    public BigInteger[] Sign(byte[] message)
    {
        BigInteger[] signature = new BigInteger[256];
        byte[] hashed = HashFunc.ComputeHash(message);

        //Need to verify bit with bit 
        for (int i = 0; i < hashed.Length; i++)
        {
            if ((hashed[i] & 0x80) == 0x80) { signature[i * 8] = privateKey[i * 8].one; }
            else { signature[i * 8] = privateKey[i * 8].zero; }

            if ((hashed[i] & 0x40) == 0x40) { signature[i * 8 + 1] = privateKey[i * 8 + 1].one; }
            else { signature[i * 8 + 1] = privateKey[i * 8 + 1].zero; }

            if ((hashed[i] & 0x20) == 0x20) { signature[i * 8 + 2] = privateKey[i * 8 + 2].one; }
            else { signature[i * 8 + 2] = privateKey[i * 8 + 2].zero; }

            if ((hashed[i] & 0x10) == 0x10) { signature[i * 8 + 3] = privateKey[i * 8 + 3].one; }
            else { signature[i * 8 + 3] = privateKey[i * 8 + 3].zero; }

            if ((hashed[i] & 0x08) == 0x08) { signature[i * 8 + 4] = privateKey[i * 8 + 4].one; }
            else { signature[i * 8 + 4] = privateKey[i * 8 + 4].zero; }

            if ((hashed[i] & 0x04) == 0x04) { signature[i * 8 + 5] = privateKey[i * 8 + 5].one; }
            else { signature[i * 8 + 5] = privateKey[i * 8 + 5].zero; }

            if ((hashed[i] & 0x02) == 0x02) { signature[i * 8 + 6] = privateKey[i * 8 + 6].one; }
            else { signature[i * 8 + 6] = privateKey[i * 8 + 6].zero; }

            if ((hashed[i] & 0x01) == 0x01) { signature[i * 8 + 7] = privateKey[i * 8 + 7].one; }
            else { signature[i * 8 + 7] = privateKey[i * 8 + 7].zero; }

            // if(i==0){
            //     Console.WriteLine("Signature");
            //     Console.WriteLine(signature[i * 8].ToByteArray().Length);
            //     PrintByteArray(signature[i * 8].ToByteArray());
            //     Console.WriteLine("SK_0");
            //     Console.WriteLine(privateKey[i * 8].zero.ToByteArray().Length);
            //     PrintByteArray(privateKey[i * 8].zero.ToByteArray());
            //     PrintByteArray(HashFunc.ComputeHash(privateKey[i * 8].zero.ToByteArray()));

            //     Console.WriteLine("SK_1");
            //     Console.WriteLine(privateKey[i * 8].one.ToByteArray().Length);
            //     PrintByteArray(privateKey[i * 8].one.ToByteArray());
            //     PrintByteArray(HashFunc.ComputeHash(privateKey[i * 8].one.ToByteArray()));
            // }   
        
        }

        return signature;
    }

    private BigInteger GenerateRandom256Bit()
    {
        byte[] array = new byte[32];
        rnd.NextBytes(array);
        return new BigInteger(array);
    }
    
    public void DumpSig(BigInteger[] sign, string filePath)
    {
        using (FileStream fs = new FileStream(filePath, FileMode.CreateNew, FileAccess.Write))
        {
            try
            {
                foreach (BigInteger b in sign)
                {
                    fs.Write(b.ToByteArray(), 0, b.GetByteCount());
                }
            }
            catch
            {

            }
        }
    }

    public void DumpPublicKey(string filePath)
    {
        using (FileStream fs = new FileStream(filePath, FileMode.CreateNew, FileAccess.Write))
        {
            try
            {
                foreach ((byte[] zero, byte[] one) keyPair in publicKey)
                {
                    fs.Write(keyPair.zero, 0, keyPair.zero.Length);
                    fs.Write(keyPair.one, 0, keyPair.one.Length);
                }
            }
            catch
            {

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