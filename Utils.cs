using System.Numerics;

public static class Utils
{
    public static byte[] ToByteArrayPadded(BigInteger b, int bytePadding)
    {
        byte[] bytes = b.ToByteArray();
        byte[] padded = new byte[bytePadding];
        Array.Copy(bytes, 0, padded, 0, bytes.Length);
        
        return padded;
    }
}