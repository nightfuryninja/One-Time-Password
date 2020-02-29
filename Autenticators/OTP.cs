using System;
using System.Collections.Generic;
using System.Text;

namespace Autenticators
{
    abstract class OTP
    {
        protected byte[] Key;

        protected OTP(byte[] Key)
        {
            this.Key = Key;
        }
        

        public abstract void GenerateOTP();
    }
}
