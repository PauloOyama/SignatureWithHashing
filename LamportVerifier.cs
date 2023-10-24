namespace signature;

using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;
using System.Diagnostics;

class LamportVerifier {
    
    private HashAlgorithm HashFunc;
    public List<(byte[], byte[])> publicKey = new List<(byte[], byte[])>();
    // public BigInteger[] signMessage = new BigInteger[];

        public LamportVerifier(HashAlgorithm HashFunc)
    {
        this.HashFunc = HashFunc;
    }

    // static void Main(){

    //     SHA256 hashFunc = SHA256.Create();
    //     LamportSigner signer = new LamportSigner(hashFunc);

    //     signer.Init();
    //     var _sign = signer.SignFile("message.txt")!;

    //     signer.DumpSig(_sign, "signature.txt");
    //     signer.DumpPublicKey("pub.txt");

    //     LamportVerifier verifier = new LamportVerifier(hashFunc);
    //     Console.WriteLine(verifier.ValidateSignatureFromFiles("message.txt", "pub.txt", "signature.txt"));

        // LamportVerifier verifier = new LamportVerifier(hashFunc);
        // using (StreamReader reader = new StreamReader(@"./message.txt")){
        //     byte[] publicKey1 = new byte[32];
        //     byte[] publicKey2 = new byte[32];
        //     byte[] verify = new byte[32];
        //     BigInteger[] num = new BigInteger[256]; 
        //     for (int i = 0; i < 3; i++){
        //         string line = reader.ReadLine()!;
        //         if(i%3 == 0){
        //             publicKey1 = Encoding.Unicode.GetBytes(line!);
        //             Console.WriteLine("PK_0"); 
        //             PrintByteArray(publicKey1);
        //         }else if(i%3==1){
        //             publicKey2 = Encoding.Unicode.GetBytes(line!);
        //             Console.WriteLine("PK_1"); 
        //             PrintByteArray(publicKey2);
        //         }else{
        //             Console.WriteLine("Signature"); 
        //             Console.WriteLine(Encoding.Unicode.GetBytes(line!).Length);
        //             PrintByteArray(Encoding.Unicode.GetBytes(line!));
        //             verify = hashFunc.ComputeHash(Encoding.Unicode.GetBytes(line!));
        //             Console.WriteLine("Hash Signature"); 
        //             Console.WriteLine(Encoding.Unicode.GetBytes(line!).Length);
        //             PrintByteArray(verify);
                    
        //             // BigInteger number = new BigInteger(line);
        //             // Console.WriteLine(number);
        //             Console.WriteLine(publicKey1.SequenceEqual(verify));
        //             Console.WriteLine(publicKey2.SequenceEqual(verify));
        //         }
        //     }  
        // }
    // }

    public bool ValidateSignatureFromFiles(string messagePath, string pubKeyPath, string signaturePath)
    {
        string msg;
        try
        {
            msg = File.ReadAllText(messagePath);
        }
        catch (FileNotFoundException e)
        {
            throw new FileNotFoundException(e.Message);
        }

        byte[] hashed = HashFunc.ComputeHash(Encoding.Unicode.GetBytes(msg));
        // Console.WriteLine("DEBUG: Read hash:");
        // PrintByteArray(hashed);

        BigInteger[] sign = new BigInteger[256];
        using (FileStream fs = new FileStream(signaturePath, FileMode.Open, FileAccess.Read))
        {
            try
            {
                int c = 0;
                while (fs.CanRead)
                {
                    byte[] buf = new byte[32];
                    fs.Read(buf, 0, 32);
                    sign[c] = new BigInteger(buf);
                    c++;
                }
            }
            catch
            {

            }
        }

        LoadPublicKeys(pubKeyPath);

        bool equal;
        for (int i = 0; i < 32; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                bool whichList = (hashed[i] & (0x80 >> j)) == (0x80 >> j);
                // Console.WriteLine($"{hashed[i] & (0x80 >> j)} {0x80 >> j}");
                if (whichList)
                {
                    byte[] oneKey = publicKey[i * 8 + j].Item2;
                    // PrintByteArray(oneKey);
                    // We're padding here because we padded on the generation of the private key as well.
                    byte[] hashedSign = HashFunc.ComputeHash(Utils.ToByteArrayPadded(sign[i * 8 + j], 32));
                    // PrintByteArray(hashedSign);
                    equal = Enumerable.SequenceEqual(oneKey, hashedSign);
                }
                else
                {
                    byte[] zeroKey = publicKey[i * 8 + j].Item1;
                    // PrintByteArray(zeroKey);
                    byte[] hashedSign = HashFunc.ComputeHash(Utils.ToByteArrayPadded(sign[i * 8 + j], 32));
                    // PrintByteArray(hashedSign);
                    equal = Enumerable.SequenceEqual(zeroKey, hashedSign);
                }

                if (equal == false)
                {
                    Console.WriteLine($"INFO: Key/Hash mismatch (list {(whichList ? 1 : 2)}) at hash byte {i} bit {8-j}\n----");
                    Console.Write("Public key (0) at bit: ");
                    PrintByteArray(publicKey[i * 8 + j].Item1);
                    Console.Write("Public key (1) at bit: ");
                    PrintByteArray(publicKey[i * 8 + j].Item2);
                    Console.Write("Signature at bit: ");
                    PrintByteArray(sign[i * 8 + j].ToByteArray());
                    Console.WriteLine("----");

                    // PrintByteArray(Utils.ToByteArrayPadded(signer.privateKey[i * 8 + j].zero, 32));
                    // PrintByteArray(Utils.ToByteArrayPadded(signer.privateKey[i * 8 + j].one, 32));
                    // PrintByteArray(HashFunc.ComputeHash(Utils.ToByteArrayPadded(signer.privateKey[i * 8 + j].zero, 32)));
                    // PrintByteArray(HashFunc.ComputeHash(Utils.ToByteArrayPadded(signer.privateKey[i * 8 + j].one, 32)));
                    return false;
                }
            }
        }

        return true;
    }

    public void LoadPublicKeys(string path)
    {
        publicKey.Clear();
        int c = 0;
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
        {
            try
            {
                while (fs.CanRead && c < 256)
                {
                    (byte[], byte[]) keyPair = (new byte[32], new byte[32]);
                    fs.Read(keyPair.Item1, 0, 32);
                    fs.Read(keyPair.Item2, 0, 32);
                    publicKey.Add(keyPair);
                    c++;
                }
            }
            catch
            {

            }
        }
        Console.WriteLine($"INFO: Verifier loaded {c} keys.");
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