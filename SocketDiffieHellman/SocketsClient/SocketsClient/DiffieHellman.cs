using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;


namespace SocketsClient
{
    class DiffieHellman
    {

        public byte[] GeneratePublicKey(int gKey, int privateKey, int nKey)
        {
            var privKey = BigInteger.ModPow(gKey, privateKey, nKey);
            return privKey.ToByteArray();
        }

        public string GeneratePrivateKey(int gaKey, int privateKey, int nKey)
        {
            var privKey = BigInteger.ModPow(gaKey, privateKey, nKey);
            return privKey.ToString();
        }

        public string DecodeMessage(byte[] bytes, byte[] key)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                int change = i + key[i];
                while (change + bytes[i] > 255) change -= 256;
                bytes[i] += (byte)change;
            }

            return Encoding.UTF8.GetString(bytes);
        }
    }
}
