using System;
using System.Collections.Generic;
using System.Text;

namespace System
{
    internal class Locale
    {
        public static string GetText(string s, params object[] arg)
        {
            return String.Format(s, arg);
        }
    }
}
