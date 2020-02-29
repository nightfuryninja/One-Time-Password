using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;


namespace Autenticators
{
    class TOTP : OTP
    {
        public int CodeLength { get; set; } = 8;
        public static int TimeFrame { get; set; } = 30;

        public TOTP(byte[] Key) : base(Key) {   }

        public override void GenerateOTP()
        {
            // We need to convert the time divided by the timeframe into a BigEndian byte array.
            long time = (long)((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);
            byte[] counter = BitConverter.GetBytes(time / TimeFrame);
            if (BitConverter.IsLittleEndian) Array.Reverse(counter);

            // We can then HMAC the counter using their key.
            HMAC hmac = new HMACSHA256(Key);
            byte[] hash = hmac.ComputeHash(counter);

            // // We need to dynamically trunacate the hash to provide the user with a code.
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            // We divide the code by 10^CodeLength and potentially pad the front with zeros to from the OTP.
            int code = (int)binary % (int)Math.Pow(10, CodeLength);
            string otp = code.ToString();
            while(otp.Length < CodeLength)
            {
                otp = "0" + otp;
            }

            Console.WriteLine(otp);
        }
    }
}
