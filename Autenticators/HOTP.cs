using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace Autenticators
{
    class HOTP : OTP
    {

        public static long Counter { private get; set; } = 0;

        public HOTP(byte[] Key, int CodeLength = 6) : base(Key, CodeLength) { }

        public override string GenerateOTP()
        {
            // We need to convert the counter into a BigEndian byte array..
            byte[] buffer = ConvertLongToBigEndianBytes(Counter);
            // We can then HMAC the counter using their key.
            byte[] hash = GenerateHMACHash(buffer);
            // We trunacate the hash into a string code.
            string otp = TrunacateOTPToString(hash);
            // We manually increment the counter.
            Counter++;
            return otp;
        }
    }
}
