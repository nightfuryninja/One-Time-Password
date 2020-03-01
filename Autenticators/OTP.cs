using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace Autenticators
{
    abstract class OTP
    {
        protected byte[] Key;
        protected int OTPLength;

        protected OTP(byte[] Key, int OTPLength)
        {
            this.Key = Key;
            this.OTPLength = OTPLength;
        }

        public abstract string GenerateOTP();

        protected byte[] GenerateHMACHash(byte[] counter)
        {
            HMAC hmac = new HMACSHA1(Key);
            byte[] hash = hmac.ComputeHash(counter);
            return hash;
        }

        protected byte[] ConvertLongToBigEndianBytes(long seed)
        {
            byte[] counter = BitConverter.GetBytes(seed);
            if (BitConverter.IsLittleEndian) Array.Reverse(counter);
            return counter;
        }

        protected string TrunacateOTPToString(byte[] hash)
        {
            // We need to dynamically trunacate the hash to provide the user with a code.
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            
            // We divide the code by 10^CodeLength to produce an output of the OTP Length.
            int code = (int)(binary % Math.Pow(10, OTPLength));
            string otp = code.ToString();
            // We pad the front with zeros until it is the right length.
            while (otp.Length < OTPLength)
            {
                otp = "0" + otp;
            }
            return otp;
        }
    }
}
