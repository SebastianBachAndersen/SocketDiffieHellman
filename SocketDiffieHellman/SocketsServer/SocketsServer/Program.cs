using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace SocketsServer
{
    class Program
    {
        static List<TcpClient> clients = new List<TcpClient>();
        public static Encryption krypteringsmaskine = new Encryption();
        public static DiffieHellman kryptering = new DiffieHellman();

        public static int g = 16;
        public static int n = 128;
        public static int priv = 34;

        public static byte[] publicKey = kryptering.GeneratePublicKey(g, priv, n);
        private static string privateKey;
        

        static void Main(string[] args)
        {
            SuckitServer();
        }
        public static void SuckitServer()
        {
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            int port = 13356;
            TcpListener listener = new TcpListener(ip, port);

            listener.Start();

            AcceptClients(listener);

            while(true)
            {
                Console.Write("Write your message here: ");
                string text = Console.ReadLine();
                byte[] buffer = Encoding.UTF8.GetBytes(text);
                
                foreach(TcpClient client in clients)
                {
                    client.GetStream().Write(krypteringsmaskine.EncryptByte(buffer, int.Parse(privateKey)), 0, buffer.Length);
                }
            }
        }
        public static async void RecieveMessage(NetworkStream stream)
        {
            byte[] buffer = new byte[256];

            int numberOfBytesRead = await stream.ReadAsync(buffer, 0, 256);
            string recievedMessage = Encoding.UTF8.GetString(krypteringsmaskine.DecryptByte(buffer, int.Parse(privateKey)), 0, numberOfBytesRead);

            Console.Write("\n" + recievedMessage);
        }
        public static async void AcceptClients(TcpListener listener)
        {
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                clients.Add(client);
                NetworkStream stream = client.GetStream();

                stream.Write(publicKey, 0, publicKey.Length);

                byte[] buffer = new byte[256];
                int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                byte[] keyfromclient = new byte[read];
                Array.Copy(buffer, 0, keyfromclient, 0, read);
                privateKey = kryptering.GeneratePrivateKey(read, priv, n);
                Console.WriteLine(privateKey.ToString()); 
                
                RecieveMessage(stream);
            }
        }
    }
}
