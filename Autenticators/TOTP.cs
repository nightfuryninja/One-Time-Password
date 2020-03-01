using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;


namespace Autenticators
{
    class TOTP : OTP
    {
        public static int TimeFrame { get; set; } = 30;

        public TOTP(byte[] Key, int OTPLength = 8) : base(Key, OTPLength) {   }

        public override string GenerateOTP()
        {
            // We need to convert the time divided by the timeframe into a BigEndian byte array.
            byte[] buffer = ConvertLongToBigEndianBytes(GetCurrentTimeInSeconds() / TimeFrame);
            // We can then HMAC the counter using their key.
            byte[] hash = GenerateHMACHash(buffer);
            // We trunacate the hash into an integer and pad the front with zeros.
            string otp = TrunacateOTPToString(hash);
            return otp;
        }

        private long GetCurrentTimeInSeconds()
        {
            long seconds = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            return seconds;
        }

        public long GetTimeTillChangeInSeconds()
        {
            long seconds = (long)(TimeFrame - (GetCurrentTimeInSeconds() % TimeFrame));
            return seconds;
        }
    }
}
