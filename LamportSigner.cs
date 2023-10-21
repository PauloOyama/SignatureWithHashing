using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

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

    static void Main()
    {
        string testString = "Hello World!";

        SHA256 hashFunc = SHA256.Create();
        byte[] hashVal = hashFunc.ComputeHash(Encoding.Unicode.GetBytes(testString));

        // PrintByteArray(hashVal);
        LamportSigner signer = new LamportSigner(hashFunc);
        signer.Init();
        Console.WriteLine(signer.privateKey.Count);
        BigInteger[] sig = signer.Sign(Encoding.Unicode.GetBytes("Badabingus."));

        Console.WriteLine(sig.Length);
    }

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

    public BigInteger[] Sign(byte[] message)
    {
        BigInteger[] signature = new BigInteger[256];
        byte[] hashed = HashFunc.ComputeHash(message);
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
        }

        return signature;
    }

    private BigInteger GenerateRandom256Bit()
    {
        byte[] array = new byte[32];
        rnd.NextBytes(array);
        // PrintByteArray(array);
        return new BigInteger(array);
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