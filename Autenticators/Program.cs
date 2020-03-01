using System;
using System.Text;
using System.Security.Cryptography;

namespace Autenticators
{
    class Program
    {
        static void Main(string[] args)
        {
            // HOTP should produce 755224
            HOTP hotp = new HOTP(Encoding.UTF8.GetBytes("12345678901234567890"));
            Console.WriteLine(hotp.GenerateOTP());

            TOTP totp = new TOTP(Encoding.UTF8.GetBytes("Key"));
            Console.WriteLine(totp.GenerateOTP());
        }
    }
}
