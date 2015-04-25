/*
 *  Optimized implementation of rehashing a MD5-Hash
 *
 *  Copyright (C) 2007  Nils Reimers (www.php-einfach.de)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */


/*
 * 32-bit integer manipulation macros (little endian)
 */



#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif


//Constant Padding Values
#define X4 128
#define X5 0
#define X6 0
#define X7 0
#define X8 0
#define X9 0
#define X10 0
#define X11 0
#define X12 0
#define X13 0
#define X14 128
#define X15 0

unsigned int X0, X1, X2, X3;


static void md5_transform()
{
    unsigned int A, B, C, D;

#define S(x,n) ((x << n) | ((x) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
{                                                       \
    a += F(b,c,d) + k + t; a = S(a,s) + b;           \
}

    A = 0x67452301;
    B = 0xEFCDAB89;
    C = 0x98BADCFE;
    D = 0x10325476;

#define F(x,y,z) (z ^ (x & (y ^ z)))

    P( A, B, C, D,  X0,  7, 0xD76AA478 );
    P( D, A, B, C,  X1, 12, 0xE8C7B756 );
    P( C, D, A, B,  X2, 17, 0x242070DB );
    P( B, C, D, A,  X3, 22, 0xC1BDCEEE );
    P( A, B, C, D,  X4,  7, 0xF57C0FAF );
    P( D, A, B, C,  X5, 12, 0x4787C62A );
    P( C, D, A, B,  X6, 17, 0xA8304613 );
    P( B, C, D, A,  X7, 22, 0xFD469501 );
    P( A, B, C, D,  X8,  7, 0x698098D8 );
    P( D, A, B, C,  X9, 12, 0x8B44F7AF );
    P( C, D, A, B, X10, 17, 0xFFFF5BB1 );
    P( B, C, D, A, X11, 22, 0x895CD7BE );
    P( A, B, C, D, X12,  7, 0x6B901122 );
    P( D, A, B, C, X13, 12, 0xFD987193 );
    P( C, D, A, B, X14, 17, 0xA679438E );
    P( B, C, D, A, X15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    P( A, B, C, D,  X1,  5, 0xF61E2562 );
    P( D, A, B, C,  X6,  9, 0xC040B340 );
    P( C, D, A, B, X11, 14, 0x265E5A51 );
    P( B, C, D, A,  X0, 20, 0xE9B6C7AA );
    P( A, B, C, D,  X5,  5, 0xD62F105D );
    P( D, A, B, C, X10,  9, 0x02441453 );
    P( C, D, A, B, X15, 14, 0xD8A1E681 );
    P( B, C, D, A,  X4, 20, 0xE7D3FBC8 );
    P( A, B, C, D,  X9,  5, 0x21E1CDE6 );
    P( D, A, B, C, X14,  9, 0xC33707D6 );
    P( C, D, A, B,  X3, 14, 0xF4D50D87 );
    P( B, C, D, A,  X8, 20, 0x455A14ED );
    P( A, B, C, D, X13,  5, 0xA9E3E905 );
    P( D, A, B, C,  X2,  9, 0xFCEFA3F8 );
    P( C, D, A, B,  X7, 14, 0x676F02D9 );
    P( B, C, D, A, X12, 20, 0x8D2A4C8A );

#undef F
    
#define F(x,y,z) (x ^ y ^ z)

    P( A, B, C, D,  X5,  4, 0xFFFA3942 );
    P( D, A, B, C,  X8, 11, 0x8771F681 );
    P( C, D, A, B, X11, 16, 0x6D9D6122 );
    P( B, C, D, A, X14, 23, 0xFDE5380C );
    P( A, B, C, D,  X1,  4, 0xA4BEEA44 );
    P( D, A, B, C,  X4, 11, 0x4BDECFA9 );
    P( C, D, A, B,  X7, 16, 0xF6BB4B60 );
    P( B, C, D, A, X10, 23, 0xBEBFBC70 );
    P( A, B, C, D, X13,  4, 0x289B7EC6 );
    P( D, A, B, C,  X0, 11, 0xEAA127FA );
    P( C, D, A, B,  X3, 16, 0xD4EF3085 );
    P( B, C, D, A,  X6, 23, 0x04881D05 );
    P( A, B, C, D,  X9,  4, 0xD9D4D039 );
    P( D, A, B, C, X12, 11, 0xE6DB99E5 );
    P( C, D, A, B, X15, 16, 0x1FA27CF8 );
    P( B, C, D, A,  X2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    P( A, B, C, D,  X0,  6, 0xF4292244 );
    P( D, A, B, C,  X7, 10, 0x432AFF97 );
    P( C, D, A, B, X14, 15, 0xAB9423A7 );
    P( B, C, D, A,  X5, 21, 0xFC93A039 );
    P( A, B, C, D, X12,  6, 0x655B59C3 );
    P( D, A, B, C,  X3, 10, 0x8F0CCC92 );
    P( C, D, A, B, X10, 15, 0xFFEFF47D );
    P( B, C, D, A,  X1, 21, 0x85845DD1 );
    P( A, B, C, D,  X8,  6, 0x6FA87E4F );
    P( D, A, B, C, X15, 10, 0xFE2CE6E0 );
    P( C, D, A, B,  X6, 15, 0xA3014314 );
    P( B, C, D, A, X13, 21, 0x4E0811A1 );
    P( A, B, C, D,  X4,  6, 0xF7537E82 );
    P( D, A, B, C, X11, 10, 0xBD3AF235 );
    P( C, D, A, B,  X2, 15, 0x2AD7D2BB );
    P( B, C, D, A,  X9, 21, 0xEB86D391 );

#undef F

 
    X0 = A+0x67452301;
    X1 = B+0xEFCDAB89;
    X2 = C+0x98BADCFE;
    X3 = D+0x10325476;
}




 void md5(unsigned char input[16], int rounds, unsigned char output[16]) {
    
    X0 =  ((unsigned int)input[0])      
            | ((unsigned int)input[1] <<  8 )       
            | ((unsigned int)input[2] << 16 )        
            | ((unsigned int)input[3] << 24 );
    
    X1 =  ((unsigned int)input[4])      
            | ((unsigned int)input[5] <<  8 )       
            | ((unsigned int)input[6] << 16 )        
            | ((unsigned int)input[7] << 24 );
    
    X2 =  ((unsigned int)input[8])      
            | ((unsigned int)input[9] <<  8 )       
            | ((unsigned int)input[10] << 16 )        
            | ((unsigned int)input[11] << 24 );
            
    X3 =  ((unsigned int)input[12])      
            | ((unsigned int)input[13] <<  8 )       
            | ((unsigned int)input[14] << 16 )        
            | ((unsigned int)input[15] << 24 );
    
    
    int i;
    for(i=0;i<rounds;++i)
        md5_transform();
    
    
    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 ); 
}





