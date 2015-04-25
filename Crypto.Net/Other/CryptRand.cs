// CryptRand.cs - A cryptographically secure pseudorandom number generator based on ISAAC

//============================================================================
// CryptoNet - A cryptography library for C#
// 
// Copyright (C) 2008  Nils Reimers (www.php-einfach.de)
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//=============================================================================

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CryptoNet
{

    /// <summary>
    /// A cryptographically secure pseudorandom number generator
    /// </summary>
    /// <example>
    /// CryptRand rng = CryptRand.Create();
    /// rng.GetBytes(buffer);
    /// </example>
    public class CryptRand : RandomNumberGenerator
    {

        public const int SIZEL = 8;
        public const int SIZE = 1 << SIZEL;
        public const int MASK = (SIZE - 1) << 2; 

        private int[] rsl;                             
        private int[] mem;
        private int count;
        private int a, b, c;

        public static readonly CryptRand Instance = new CryptRand();


        private CryptRand()
        {
            rsl = new int[SIZE];
            mem = new int[SIZE];

            //Seed generation
            GenerateSeed();

            RandInit();
        }

        public static new CryptRand Create()
        {
            return Instance;
        }

        public static new CryptRand Create(string rngName)
        {
            return Create();
        }



        [DllImport("kernel32.dll")]
        private static extern int GetTickCount();

        [DllImport("kernel32.dll")]
        private static extern int GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
      
        
        
        
        //Generates a seed, depending on time, process properties and system properties
        private void GenerateSeed()
        {
            SHA512 sha = SHA512Managed.Create();

            int tid, mTid, pid, osStart, pCount, sid;
            long query, ticks, pStart;
            long mem1, mem2, mem3, mem4, mem5, mem6;

            tid = mTid = pid = osStart = pCount = sid = 0;
            query = ticks = pStart = mem1 = mem2 = mem3 = mem4 = mem5 = mem6 = 0;

            try
            {
                tid = GetCurrentThreadId(); //ThreadID
                mTid = Thread.CurrentThread.ManagedThreadId; //ManagedThreadID
                pid = Process.GetCurrentProcess().Id; //ProcessID              
                osStart = GetTickCount(); //Milliseconds since system start
                pCount = Process.GetProcesses().Length; //Number of processes
                sid = Process.GetCurrentProcess().SessionId; //Session ID
            }
            catch { }

            try
            {
                QueryPerformanceCounter(out query); //QueryPerformanceCounter
                ticks = DateTime.Now.Ticks; //Current time in nanoseconds since the 1.1.1
                pStart = Process.GetCurrentProcess().StartTime.Ticks; //start time of the process
            }
            catch { }
            


            //Memory values            
            try
            {
                mem1 = Process.GetCurrentProcess().PagedMemorySize64;
                mem2 = Process.GetCurrentProcess().PagedSystemMemorySize64;
                mem3 = Process.GetCurrentProcess().PeakPagedMemorySize64;
                mem4 = Process.GetCurrentProcess().PeakVirtualMemorySize64;
                mem5 = Process.GetCurrentProcess().PeakWorkingSet64;
                mem6 = Process.GetCurrentProcess().VirtualMemorySize64;
            }
            catch { }
                       
            
            //Details of user and computer
            string user = "";
            try
            {
                user = Process.GetCurrentProcess().ProcessName +
                               Process.GetCurrentProcess().MachineName +
                               System.Environment.UserName +
                               System.Environment.MachineName +
                               System.Environment.OSVersion.ToString() +
                               System.Environment.StackTrace +
                               System.Environment.Version.ToString() +
                               System.Environment.UserDomainName +
                               System.Environment.WorkingSet.ToString();
            }
            catch { }

            StringBuilder processInfos = new StringBuilder();


            //Using informations from other processes
            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        processInfos.Append(p.Id.ToString());
                        processInfos.Append(p.Handle.ToString());
                        processInfos.Append(p.HandleCount.ToString());
                        processInfos.Append(p.MainModule.FileName);
                        processInfos.Append(p.Modules.Count.ToString());
                        processInfos.Append(p.MainWindowTitle);
                        processInfos.Append(p.NonpagedSystemMemorySize64.ToString());
                        processInfos.Append(p.PagedMemorySize64.ToString());
                        processInfos.Append(p.PagedSystemMemorySize64.ToString());
                        processInfos.Append(p.PeakPagedMemorySize64.ToString());
                        processInfos.Append(p.PeakVirtualMemorySize64.ToString());
                        processInfos.Append(p.PeakWorkingSet64.ToString());
                        processInfos.Append(p.PrivateMemorySize64.ToString());
                        processInfos.Append(p.PrivilegedProcessorTime.ToString());
                        processInfos.Append(p.ProcessName);
                        processInfos.Append(p.StartTime.Ticks.ToString());
                        processInfos.Append(p.Threads.Count.ToString());

                        for (int i = 0; i < p.Threads.Count; i++)
                        {
                            processInfos.Append(p.Threads[i].CurrentPriority.ToString());
                            processInfos.Append(p.Threads[i].Id.ToString());
                            processInfos.Append(p.Threads[i].StartAddress.ToString());
                            processInfos.Append(p.Threads[i].StartTime.Ticks.ToString());
                            processInfos.Append(p.Threads[i].TotalProcessorTime.TotalMilliseconds.ToString());
                            processInfos.Append(p.Threads[i].UserProcessorTime.TotalMilliseconds.ToString());
                        }
                        processInfos.Append(p.TotalProcessorTime.TotalMilliseconds.ToString());
                        processInfos.Append(p.UserProcessorTime.TotalMilliseconds.ToString());
                        processInfos.Append(p.VirtualMemorySize64.ToString());
                        processInfos.Append(p.WorkingSet64.ToString());
                    }
                    catch { }

                }
            }
            catch { }
            

            unchecked
            {
                rsl[0] = tid;
                rsl[1] = mTid;
                rsl[2] = pid;
                rsl[3] = osStart;
                rsl[4] = pCount;
                rsl[5] = sid;

                rsl[6] = (int)(query & 0xFFFFFFFF);
                rsl[7] = (int)(query >> 32);

                rsl[8] = (int)(ticks & 0xFFFFFFFF);
                rsl[9] = (int)(ticks >> 32);

                rsl[10] = (int)(pStart & 0xFFFFFFFF);
                rsl[11] = (int)(pStart >> 32);

                rsl[12] = (int)(mem1 & 0xFFFFFFFF);
                rsl[13] = (int)(mem1 >> 32);

                rsl[14] = (int)(mem2 & 0xFFFFFFFF);
                rsl[15] = (int)(mem2 >> 32);

                rsl[16] = (int)(mem3 & 0xFFFFFFFF);
                rsl[17] = (int)(mem3 >> 32);

                rsl[18] = (int)(mem4 & 0xFFFFFFFF);
                rsl[19] = (int)(mem4 >> 32);

                rsl[20] = (int)(mem5 & 0xFFFFFFFF);
                rsl[21] = (int)(mem5 >> 32);

                rsl[22] = (int)(mem6 & 0xFFFFFFFF);
                rsl[23] = (int)(mem6 >> 32);


                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(user));

                for (int i = 0; i < (hash.Length / 4); i++)
                    rsl[24 + i] = ((int)hash[4 * i]) << 24 | ((int)hash[4 * i + 1]) << 16 | ((int)hash[4 * i + 2]) << 8 | ((int)hash[4 * i + 3]);

                //Delete hashvalue
                for (int i = 0; i < hash.Length; i++)
                    hash[i] = 0x00;


                hash = sha.ComputeHash(Encoding.UTF8.GetBytes(processInfos.ToString()));
                for (int i = 0; i < (hash.Length / 4); i++)
                    rsl[40 + i] = ((int)hash[4 * i]) << 24 | ((int)hash[4 * i + 1]) << 16 | ((int)hash[4 * i + 2]) << 8 | ((int)hash[4 * i + 3]);


                

                int startPos = 40 + (hash.Length / 4);

                byte[] rand = new byte[(rsl.Length - startPos) * 4];
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                rng.GetBytes(rand);

                for (int i = startPos, j = 0; i < rsl.Length; i++, j += 4)                
                    rsl[i] = (rand[j] << 24 | rand[j + 1] << 16 | rand[j + 2] << 8 | rand[j]) ^ rsl[i % startPos];
                


                //Delete secret data
                for (int i = 0; i < rand.Length; i++)
                    rand[i] = 0x00;

                for (int i = 0; i < hash.Length; i++)
                    hash[i] = 0x00;


                tid = mTid = pid = osStart = pCount = sid = 0;
                query = ticks = pStart = mem1 = mem2 = mem3 = mem4 = mem5 = mem6 = 0;
                user = null;
            }            

        }

        /*
         * ISAAC is a pseudorandom number generator designed by Bob Jenkins in (1996)
         * to be cryptographically secure.
         * It uses an array of 256 4-byte integers (called mm) as the internal state, 
         * writing the results to another 256-integer array
         */
        private void Isaac()
        {
            int i, j, x, y;

            b += ++c;
            for (i = 0, j = (SIZE>>1); i < (SIZE>>1); )
            {
                x = mem[i];
                a ^= a << 13;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 6);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= a << 2;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 16);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
            }

            for (j = 0; j < (SIZE>>1); )
            {
                x = mem[i];
                a ^= a << 13;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 6);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= a << 2;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 16);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
            }
        }


        //Init ISAAC
        private void RandInit()
        {
            int i;
            int a, b, c, d, e, f, g, h;
            a = b = c = d = e = f = g = h = unchecked((int)0x9e3779b9);                 

            for (i = 0; i < 4; ++i)
            {
                a ^= b << 11; d += a; b += c;
                b ^= (int)((uint)c >> 2); e += b; c += d;
                c ^= d << 8; f += c; d += e;
                d ^= (int)((uint)e >> 16); g += d; e += f;
                e ^= f << 10; h += e; f += g;
                f ^= (int)((uint)g >> 4); a += f; g += h;
                g ^= h << 8; b += g; h += a;
                h ^= (int)((uint)a >> 9); c += h; a += b;
            }

            /* initialize using the contents of r[] as the seed */
            for (i = 0; i < SIZE; i += 8)
            {              
                a += rsl[i]; b += rsl[i + 1]; c += rsl[i + 2]; d += rsl[i + 3];
                e += rsl[i + 4]; f += rsl[i + 5]; g += rsl[i + 6]; h += rsl[i + 7];
               
                a ^= b << 11; d += a; b += c;
                b ^= (int)((uint)c >> 2); e += b; c += d;
                c ^= d << 8; f += c; d += e;
                d ^= (int)((uint)e >> 16); g += d; e += f;
                e ^= f << 10; h += e; f += g;
                f ^= (int)((uint)g >> 4); a += f; g += h;
                g ^= h << 8; b += g; h += a;
                h ^= (int)((uint)a >> 9); c += h; a += b;
                mem[i] = a; mem[i + 1] = b; mem[i + 2] = c; mem[i + 3] = d;
                mem[i + 4] = e; mem[i + 5] = f; mem[i + 6] = g; mem[i + 7] = h;
            }


            /* do a second pass to make all of the seed affect all of m */
            for (i = 0; i < SIZE; i += 8)
            {
                a += mem[i]; b += mem[i + 1]; c += mem[i + 2]; d += mem[i + 3];
                e += mem[i + 4]; f += mem[i + 5]; g += mem[i + 6]; h += mem[i + 7];
                a ^= b << 11; d += a; b += c;
                b ^= (int)((uint)c >> 2); e += b; c += d;
                c ^= d << 8; f += c; d += e;
                d ^= (int)((uint)e >> 16); g += d; e += f;
                e ^= f << 10; h += e; f += g;
                f ^= (int)((uint)g >> 4); a += f; g += h;
                g ^= h << 8; b += g; h += a;
                h ^= (int)((uint)a >> 9); c += h; a += b;
                mem[i] = a; mem[i + 1] = b; mem[i + 2] = c; mem[i + 3] = d;
                mem[i + 4] = e; mem[i + 5] = f; mem[i + 6] = g; mem[i + 7] = h;
            }
      

            Isaac();
            count = 0;
        }


        //Is the buffer of random bytes empty?
        private void CheckCount()
        {
            if (count > ((SIZE << 2)-1))
            {
                Isaac();
                count = 0;
            }
        }


        public int Next()
        {
            CheckCount();

            if ((count &3) != 0)
                count += 4-(count & 3);

            count += 4;

            return rsl[(count-4)>>2];
        }

        public byte NextByte()
        {
            CheckCount();            

            int val = rsl[count >> 2];
            int index = (count & 3)<<3;

            count++;

            return (byte)((val & (0xFF000000 >> index)) >> (24-index));
            //return (byte)((val & (0xFF << index)) >> index);
        }

        public override void GetBytes(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] = NextByte();
        }

        public override void GetNonZeroBytes(byte[] data)
        {
            for (int i = 0; i < data.Length; )
            {
                data[i] = NextByte();
                if (data[i] != 0)
                    i++;
            }            
        }


#if DEBUG
        /// <summary>
        /// DONT'T!! call this method!
        /// It's only for unit-testing
        /// 
        /// This methode takes away the randomness of
        /// the RandomNumberGenerator, because its clear the
        /// seed and the sequence of random bytes would always
        /// be the same.
        /// 
        /// This method is just for unit-testing, to test, whether
        /// the algorithm works correct.
        /// </summary>
        internal void PrepareUnitTesting1()
        {
            rsl = new int[SIZE];
            mem = new int[SIZE];
            a = b = c = count = 0;

            RandInit();

            Isaac();
        }

        /// <summary>
        /// DONT'T!! call this method!
        /// It's only for unit-testing
        /// 
        /// This methode takes away the randomness of
        /// the RandomNumberGenerator, because its clear the
        /// seed and the sequence of random bytes would always
        /// be the same.
        /// 
        /// This method is just for unit-testing, to test, whether
        /// the algorithm works correct.
        /// </summary>
        internal void PrepareUnitTesting2()
        {
            rsl = new int[SIZE];
            mem = new int[SIZE];
            a = b = c = count = 0;

            //Seed from 'randtest.c': "This is <i>not</i> the right mytext."
            rsl[0] = 0x73696854;
            rsl[1] = 0x20736920;
            rsl[2] = 0x6e3e693c;
            rsl[3] = 0x2f3c746f;
            rsl[4] = 0x74203e69;
            rsl[5] = 0x72206568;
            rsl[6] = 0x74686769;
            rsl[7] = 0x74796d20;
            rsl[8] = 0x2e747865;

            RandInit();

            //Isaac();
        }
#endif
    }
}
