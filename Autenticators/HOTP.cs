using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace Autenticators
{
    class HOTP : OTP
    {

        public static long Counter { private get; set; } = 0;

        public static int CodeLength { get; set; } = 6;

        public HOTP(byte[] Key) : base(Key) { }

        public override void GenerateOTP()
        {
            // We need to convert the counter into a BigEndian byte array..
            byte[] seed = BitConverter.GetBytes(Counter);
            if (BitConverter.IsLittleEndian) Array.Reverse(seed);
            
            // We can then HMAC the counter using their key.
            HMAC hmac = new HMACSHA1(Key);
            byte[] hash = hmac.ComputeHash(seed);
            
            // We need to dynamically trunacate the hash to provide the user with a code.
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

            // We divide the code by 10^CodeLength to produce an output of the CodeLength.
            // We divide the code by 10^CodeLength and potentially pad the front with zeros to from the OTP.
            int code = (int)binary % (int)Math.Pow(10, CodeLength);
            string otp = code.ToString();
            while (otp.Length < CodeLength)
            {
                otp = "0" + otp;
            }

            Console.WriteLine(code);
            // We manually increment the counter.
            Counter++;
        }
    }
}
