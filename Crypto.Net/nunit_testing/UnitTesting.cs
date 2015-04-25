// UnitTesting.cs - Testsuite of CryptoNet with NUnit

//============================================================================
// CryptoNet - A cryptography library for C#
// 
// Copyright (C) 2007  Nils Reimers (www.php-einfach.de) / Crypto.Net
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
using System.Security.Cryptography;
using System.IO;


// Compile this project with DEBUG enviroment setting. 
// The nunit.framework.dll have to be in the same folder.
#if DEBUG
using NUnit.Framework;
namespace CryptoNet.nunit_testing
{

    //UnitTest to verify the correct implementations of the different algorithm

    [TestFixture]
    public class UnitTesting
    {
        CryptRand rand = CryptRand.Instance;

#region RSA Test
       

        [Test]
        public void RSAManagedTest()
        {
           
            
            RSAManaged rsa = new RSAManaged();
            RSACryptoServiceProvider rsaMS = new RSACryptoServiceProvider();
            //RSA rsaMS = RSA.Create();

            byte[] plain = new byte[5];
            byte[] cipher;
            byte[] decipher;

            for(int i=0;i<10; i++)
            {
                plain = new byte[32 + (i * 8)];
                rand.GetBytes(plain);
                cipher = rsa.EncryptValue(plain, true);
                decipher = rsa.DecryptValue(cipher, true);

                Assert.AreEqual(plain, decipher, "Error in RSAManaged");              
            }


            
            cipher = rsa.EncryptValue(plain, false);
            decipher = rsaMS.Encrypt(plain, false);

            rsaMS.FromXmlString(rsa.ToXmlString(true));

            Assert.AreEqual(rsaMS.ToXmlString(true), rsa.ToXmlString(true), "Import Export");

            for (int i = 0; i < 1; i++)
            {
                plain = new byte[32 + (i * 8)];
                rand.GetBytes(plain);
                cipher = rsa.EncryptValue(plain, false);
                decipher = rsaMS.Encrypt(plain, false);
                Array.Reverse(decipher);

                Assert.AreEqual(cipher, decipher, "Cannot decrypt: RSAManaged to RSACryptoServiceProvider");
            }
            

          /*  rsa = new RSAManaged();
            rsaMS = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaMS.ToXmlString(true));*/
            /*for (int i = 0; i < 10; i++)
            {
                plain = new byte[32 + (i * 8)];
                rand.GetBytes(plain);
                cipher = rsaMS.EncryptValue(plain);
                decipher = rsa.DecryptValue(cipher);

                Assert.AreEqual(plain, decipher, "Cannot decrypt: RSAManaged to RSACryptoServiceProvider");
            }*/
            

        }

        [Test]
        public void RSASimpleTest()
        {
            RSASimple rsaServer = new RSASimple();
            RSASimple rsaClient = new RSASimple();

            rsaClient.ImportKey(rsaServer.ExportKey(false));

            for (int i = 0; i < 10; i++)
            {
                string plain = "Testvalue".PadRight(i * 100, 'P');
                string cipher = rsaClient.Encrypt(plain);
                string decipher = rsaServer.Decrypt(cipher);

                Assert.AreEqual(plain, decipher);
            }
        }
        #endregion

#region DiffieHellman
        [Test]
        public void DiffieHellmanTest()
        {
            DiffieHellmanManaged Alice = new DiffieHellmanManaged();
            DiffieHellmanManaged Bob = new DiffieHellmanManaged();

            //1. Step: Generating A = g^a mod p and B = g^b mod p (a and b are random numbers)
            byte[] A = Alice.CreateKeyExchange();
            byte[] B = Bob.CreateKeyExchange();

            //2. Step: Alice has to send A to Bob and Bob has to send B to Alice
            byte[] secretKeyAlice = Alice.DecryptKeyExchange(B);
            byte[] secretKeyBob = Bob.DecryptKeyExchange(A);

            Assert.AreEqual(secretKeyAlice, secretKeyBob, "Secret Keys are different");
        }
        #endregion

#region Hash Algorithm Tests
        [Test]
        public void KeyStrengtheningTest()
        {
            KeyStrengthening md5 = new KeyStrengthening(100, KeyOutputLength._128);
            KeyStrengthening sha1 = new KeyStrengthening(100, KeyOutputLength._160);
            KeyStrengthening sha256 = new KeyStrengthening(100, KeyOutputLength._256);

            MD5 md5Check = MD5.Create();
            SHA1 sha1Check = SHA1.Create();
            SHA256 sha256Check = SHA256.Create();

            byte[] hash; byte[] controlHash;
            byte[] input = new byte[32];

            rand.GetBytes(input);

            //MD5
            hash = md5.ComputeHash(input);
            controlHash = md5Check.ComputeHash(input);

            for (int i = 0; i < 100; i++)
                controlHash = md5Check.ComputeHash(controlHash);

            Assert.AreEqual(hash, controlHash, "Error in MD5");

            //SHA1
            hash = sha1.ComputeHash(input);
            controlHash = sha1Check.ComputeHash(input);

            for (int i = 0; i < 100; i++)
                controlHash = sha1Check.ComputeHash(controlHash);

            Assert.AreEqual(hash, controlHash, "Error in SHA1");

            //SHA256
            hash = sha256.ComputeHash(input);
            controlHash = sha256Check.ComputeHash(input);

            for (int i = 0; i < 100; i++)
                controlHash = sha256Check.ComputeHash(controlHash);

            Assert.AreEqual(hash, controlHash, "Error in SHA256");
            
        }

        [Test]
        public void SecurePasswordHashTest()
        {
            SecurePasswordHash secureHash = new SecurePasswordHash();
            string pw = "secret";
            string hash = secureHash.ComputeHash(pw);

            Assert.IsTrue(secureHash.ComparePassword(pw, hash), "correct pw was declared as wrong");
            Assert.IsFalse(secureHash.ComparePassword("wrong pw", hash), "wrong pw was declared as a correct pw");
        }

        [Test]
        public void HMACTest()
        {
            byte[] result, correctResult;
            HMAC hmac;

            //RFC 2202 (http://www.ietf.org/rfc/rfc2202.txt)
            hmac = new HMAC(new MD5CryptoServiceProvider());
            hmac.Key = GetBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            result = hmac.ComputeHash("Hi There");

            correctResult = GetBytes("9294727a3638bb1c13f48ef8158bfc9d");
            Assert.AreEqual(result, correctResult, "Error in HMAC-MD5-1");

            hmac = new HMAC(new SHA1Managed());
            hmac.Key = GetBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            result = hmac.ComputeHash("Hi There");

            correctResult = GetBytes("b617318655057264e28bc0b6fb378c8ef146be00");
            Assert.AreEqual(result, correctResult, "Error in HMAC-SHA-1");
        }

        #endregion

#region CryptRand Test

        //
        // RandomNumberGeneratorTest.cs - NUnit Test Cases for RNG
        //
        // Author:
        //	Sebastien Pouliot  <sebastien@ximian.com>
        //  Modified by Nils Reimers for CrypttoSharp
        //
        // (C) 2002 Motus Technologies Inc. (http://www.motus.com)
        // Copyright (C) 2006 Novell, Inc (http://www.novell.com)
        //

        private byte[] sample;
       


        [Test]
        public void CryptRandTest()
        {
            //Verfiy that CryptRand/ISAAC produce "randomnumbers"
            CryptRandTestSetUp();
            CryptRandMonobit();
            CryptRandPoker();
            CryptRandRuns();
            CryptRandLongRuns();


            //Verfiy the correct implementation of the ISAAC-Algorithm
#region Correct Result
            string correctResult1 =
@"f650e4c8e448e96d98db2fb4f5fad54f433f1afbedec154ad837048746ca4f9a
5de3743e88381097f1d444eb823cedb66a83e1e04a5f6355c744243325890e2e
7452e31957161df638a824f3002ed71329f5544951c08d83d78cb99ea0cc74f3
8f651659cbc8b7c2f5f71c6912ad6419e5792e1b860536b809b3ce98d45d6d81
f3b2612917e38f8529cf72ce349947b0c998f9ffb5e13dae32ae2a2bf7cf814c
8ebfa303cf22e0640b923200eca4d58aef53cec4d0f7b37d9c411a2affdf8a80
b40e27bcb4d2f97644b89b08f37c71d51a70e7e90bdb9c3060dc5207b3c3f24b
d7386806229749b54e232cd091dabc65a70e11018b87437e5781414fcdbc62e2
8107c9ff69d2e4ae3b18e752b143b6886f4e077295138769943c3c74afc17a97
0fd439636a529b0bd8c58a6aa8bcc22d2db35dfea7a2f4026cb167db538e1f4e
7275e2771d3b8e97ecc5dc9115e3a5b90369661430ab93ecac9fe69d7bc76811
60eda8da28833522d5295ebc5adb60e7f7e1cdd097166d14b67ec13a210f3925
64af0fef0d0286843aea3decb058bafbb8b0ccfcf2b5cc05e3a662d9814bc24c
2364a1aa37c0ed052b36505c451e7ec85d2a542fe43d0fbb91c8d92560d4d5f8
12a0594b9e8a51dacd49ebdb1b0dcdc1cd57c7f7e63444517ded386f2f36fa86
a6d1210133bc405db388d96cdb6dbe96fe29661c13edc0cbcb0eee4a70cc94ae
de11ed340606cf9f3a6ce38923d74f4ea37f63ff917bdec2d73f72d40e7e0e67
3d77d9a213add9228891b3db01a9bd7056a001e3d51f093dcc033ce35ad0d3b0
34105a8c6a123f57bd2e50247364944be89b1a3b21835c4d9f39e2d9d405ded8
294d37e5bccaaeed35a124b56708a2bcb00960ba2a98121a4d8fae820bb3263f
12595a196a1075890809e49421c171ec884d682514c8009bb0b84e7b03fb88f4
28e7cb789388b13bdd2dc1d5848f520a07c28cd168a3935872c9137d127dd430
c613f1578c2f0d55f7d3f39f309bfb788406b13746c0a6f53718d59708607f04
76904b6d04db4e13cd7411a7b510ce0ebfc7f7ccb83f957afdfef62dc35e4580
3ff1e5244112d96c02c9b944d5990dfbe7e265810d9c7e7e826dfa8966f1e0ab
30bcc764eadebeaced35e5ee0c571a7de4f3a26af7f58f7badf6bc235d023e65
1ed3ff4eec46b0b6d2a93b51e75b41c97e315aeb61119a5a53245b7933f6d7b1
cae8deba50fc8194afa92a6dc87c80064188bfcd8bace62e78ffa5685597ec0f
b4415f7d08294766ad56764309c36f903dde9f394a0a283c18080c8e080c79ec
79ae4c10cb9e15637cdd662f62d31911a4ca0cf15cf824cd3b708f991e16614c
b6b9d7665de87abb7229ea81d5b2d75056e6cd21fe1e42d596da2655c2b9aa36
b8f6fd4a6a158d1001913fd3af7d1fb80b5e435f90c107576554abda7a68710f
82ac484fd7e1c7be95c85eaa94a302f44d3cfbda786b29081010b27582d53d12
21e2a51c3d1e9150b059261dd0638e1a31860f0581f2864dff4cfc350451516d
bd086f26bc5654c165dfa427a82427f5582e3014b8d2486dc79a17499a1d7745
8766bb541e04a7f73d3dff8ad5ec6bf4dbef7d9f36ec0ea31feb2e4f15cfcc5c
d8c423fbd0ef3cc9eb244925ba5590c8a5f48ac433c5321c613b67b2479c3a22
e21339cc10d210aa931dd7e2ef05ee06b82f2703a385cb2c5d67133c877eb7b4
1e3437f75afb43ae53c078f394d904811d96458908063a85e13222281956b1e5
31860f132e7b022f21182ca396f703ac46819e2e0d28fe523724d4dca0eabe6b
c66699fdc6112fdd19c1e69c04d3658a4b55dd9931907d62f854b5224d678f26
22ae0582eafed133e4a51d2184bd6dd6c1a513753f28ee63fb737b1a70a1660e
8a8dfaa31be79937f7476978513c1764531ac6bf12c06908001cdb951a4b6a53
d067fce512b2cfb69ddb477f740e006639ddf25acc8bfa2df1b20eaf64f2632c
9783cdee63bfd4d80084cfe575f4e9e219b48fd06c48ddd87a36af9371865c4c
9ce0199d867027d72cb7b77f84ef01da72f5972f040f7074df9afa29c921f94e
75c08a3618c1ef9ad649a428c5b719378a30738ad97cd348858129a6239e3b0a
bbb8abc480fac4c2ecfcf20bd9d711f9e2a4ef71b5fe87c0be8b06b2aafef5a7
9c15db3b0aeb81654389a84a253b1d7a19047c797cdc78a2d20adf0356f55a71
3e730fa8fd8650d8959e234eb7546681dad1b22a142a6e858ef4bce668235b9d
85a13f8574096ae7a949bea229322d0dd568385882846526403dae086dd1943a
e1279bff9e7e4f041c3a4524484525e481d4cc5fe24124c0037464c0bf1bd691
26ceb003275ead3ac5bde90826414ff3a30519add7b43abe2ce5d3d588412761
97ca2070e5fbb9c7276df0b4308f751f37a97df6c9cd808cfe4cb3803d469303
aee19096c0d5d42a4e823ad3f5f9cc3b4286619c9ca45e1c66c97340891aec49
45bae606c798f04752649d6cce86fdfc80c6e402d6ec2f2b27c822821fe26ce0
92f57ea7de462f4d07497cae5a48755c721502dd6cbe7935836d80039ead7f70
9ab3a42f4c8652d632e39273e8fa38601da4f25a0cd6ef8102503f7d8854a0a1
9a30c4e88815715305efe29457c4c9252887d96fc1a71e3ce9f841632d0985de
d21e796c6fb5ce5602614abfc3c7be2cb54fed6fa617a083c3142d8f6079e4ce
ceffc1471d0cb81bdc153e5fe36ef5bbd531161a165b10157aa114ed3f7579b3
f7f395f1bc6172c7a86f875e0e6c51b3cdfec2af73c0e762824c2009c5a87748
94d401258aba3ffbd32be0608c17eff021e2547e07cffad905340e15f3310c92
9d8d190886ba527ff943f672ef73fbf046d95ca5c54cd95b9d855e894bb5af29";

            string correctResult2 =
@"c9d3bc515bc2433923e22e3a5659b89a21c6dcfd168e10a41df755f699d3a910
f48f0656e9431f57839c384b238bac78d3693e2a96e06a6f1358bb9e6872ff7f
75f9a3919d951a6f4460a8a12818c604459b44fce4eeacbfb13edb9c38f9a0c4
9b6c882d44ddb7986a02781b464d8241b6e89c5bee627b944b5cf183030800c9
63e24cba9582bdaa8b038c2c5bcc29d7ab4e83697874b2421302a96dec44d5cc
6cc59d039abc6857ea100737c567708fb25912b453899438b33ba5c008d848bc
e32573ca1190acf5d015c2e7be2f137f2f059bb682ca6f0a39172da59bcb3a5b
8288cd542f7a6e72371ac5973c9c00e1584ae4627420bf5eb3e7eeb3cb1f301d
89f7548d5c758f6e5e5689f4fda0ec6bd080797ec8ce8e0e08ed5b1a75f4dca7
c03c8d08ad11d474cb4ee33a6588dd1ee71dd73d25b36d83c2a014ee1f1be022
97748d52ba47b4b2b5b0f69f9092902e8cc370f9a65b687fbb8ad1473c532186
25ff761bf507c27cafb181083b8e7ade3044df96f5b51be4b8b3895f56ad9f82
13cf0045adbbcd41ba984c48ac14915f4dea8a1c70240f6e46e5085b44995e68
d49a2785bec2118433bd320928b6c25f8aaa592c642844ebb2a8bf4fb62c21b4
1ed940715047c2049966bf9854d6a1ded3b08718602cdd1e27d3b289f5284ba7
e552480eb4317128a6a831c7ef98ba77082e2387a60f81871bdda376d11b59d2
0b2adb585f07968d635655556eaaa2da43de6b6d86d498ffe349229087aa3a05
4ea8d3b5bb9fe9a1798b22223e77c27ed263434e82d504cb5936c07b82b93bcb
40e1ddc4fed24c095e66d6e5b3f09f1d812b901c99b87e3b7ac6b7ed30d63060
7508dc03a42248a9ad313fdf3a4e945cac8754600940e8179f71db1fed35bebe
29c77c3179e42f94a3dbcd7940651421d9af685366b9ecc19d93f3c4a38e3003
181e1ab7c952f8efdfaebb9e91a5021595590c72d2d2db407a4792429ae6f3dc
6d6ee596f0ccabd550367e9eaf96bafac4940ecd63a82778e40950a9fabf9e2c
f91450e91ad83713795209f69f7d8ca0c4cd930c2ac7c086a24e2dab8b7a3616
b691e3ecf30e76313f09c2584ea46c5ad799e7d875d3fa5d17966f6cb9f30b32
da1e3c67ab3dc36ad3a47ef3483013620df21a5c38731862a8b52636f4b7ab4f
b709addd0642b616645c68bb7defde20c7eb832ec5d9d39ec52256e5992300b4
c581df99a642f4aad4f0ba8794b9d83092c4ced6a74b776e87d32645dab3bd5f
99f8eec0e0457735b44c5c9295688a533856aae83352431d77449906011d7f76
936df33e5de7c3462f6039f805795322d6b648879f812dab416c484dc63687a5
b0658c71772bfea53ed63727cc03377f2d65837440597e84ef62dfaa3ba989b7
d1b26dc5d3a7f5e1e5de149f9c26e15a634777913c7a0855f00990ddcb673179
587599242be2c27303165f2ee4f4832b88fa93d2cc096c83fb713a2199aa55bd
eae7f35dddaf236cda0552ced2fb442ffd1ac65ea680c86c7a9f36c0a5ccce35
8060b929e2a6a2da6817533518859b40d2b4213b97a896c0119d3659bc89d7b1
8feb1ca468329ee65881583dcd58805e2621ab01f0b07a6b88307d3075b6547d
40c991978916ae7d7f623b33951c03962bc389d380f0a93dfaa5640abd5a6773
86c411ae80171a7ecc27f2ec6ea7df3324bd0f91e5a1e0a92f32057e3cb4da7c
025b3f1a4f04f06df662966859e4708af93cb92fbdefd4bea305c6ccd7aa0586
c6a074a1fd3e7ab15c3fe3a8ec5ad004e5b2aedde4b6e6b7ef7a21443f9e2ab2
9e23140aa5f2733f1db7d2ab365a36988d01cc58f31bf73bafcba5b3d2eaf84c
54a0200d7df1f1ef6e6a858c0cc1c65cadd26e2d86e027833aa30e3f221249e9
0ca77c211b4deef672d63e5cdb48a3670dbc58d3d611e8074bb9d5ff445beeb0
5832645091924ae24027ff305ed0ab3438580f9d4124eeac5ba2bd88be7154aa
b66952bde6a08935115712dac27c05d0ea230b0ecc80600ac670034c8dbb11bc
42b780c18491adf6e649f1c59d39fc1563820ed660e6a30638ebf6c4f537d52c
98453ad16958ce2891c47f60c791d92c9f7a347fa58743d06b6739cf30bb95b1
890c0c5215a8b715103cfae246bb7f76d86585a4c1680e03b1aad2a1d56f19ad
ffa33b126506373d16096bc8ae81b350993096a241b7a646f4f4e7820ba9ef2e
0a90c635363b3142469afd16747bf4fbcc4d3f57343ca09e849c719dc26d6463
3f9309b8f9d86bb69eb1737841a37a968c23612c7a6a50e729c858ff01d94ceb
fd154ca7f36e5b9341c241797e85062127881f8ccbb4854e6c4bb0757a9b2efd
30e57d5b3e21b8666be35753756b24861e444d3119a4dc7bb25395231ba56f3c
a57cfeac2dca089468d2dae48eba2481ecb9c40594bd6ba27bb4392c16907ad2
253f9a3910f05c5976300440dafe359453c2a3bb6fb3b5a96c5988806292e448
81a97eb731714189133bdb20a2438d5439481d9f07c72fc32fa9698b6a6d2133
8594d9b671704614177a0b8e6e90b22c87f7aeff3c561f6da923ddbd73250219
3738d0d19f765c9bb733529f215fa15b77308fefd1b2ad98b59441fd395882d2
37e8cb59bbfc6d294b860cebe884d62afcbed67244752a76a57a2a4d635b1a64
2598ed261f437c1dfb72da0ab3518deb79dcd4069614d1d140a94e5ada4ef12f
a986e219ccc2276e7d3565aaa3e84df3f85ec4164647abf3f38179fd3aebddd0
3b7b1612aaac1068e6e356e70d42ed8e52802d42d404fa1fd02058d187089208
efcd8c831580ea863fadf252b136ccae1b1fe1f24b120e966721bb2d37408741
c808db8967683003a432fad5d296460f5f7af6708c1c6a0e96f7e89234c2bee1
82bfb1101f91280a3a62acb04dd2dde65f1bfa9ee0fa99438afe9c4d7b4ed2eb
a30c0d496a5d63cb4b8cbd22fd29c18d9f1dea21cece3d8aa1e7419163a209df
ac074eeea68b1bb0d4d627abbe49590333ceaf65849a94e334ccfa615c53d80d
a185837269ef266daf68ef0856453458faf982b7f85a0427322a55f225ae65df
2d9b56c850db1350c20f1c2e3af50ad045768784b220d5502e8a32f6176afab5
ba64e5bdb0e70111ce9127d8725a471a88b2112d2392e3d87b73526a7b406495
07e522a796edd53c417c9383a3e38188448c71ec3b8e482ed83e8c22d1e71c06
9133704027bac9971b7bb4286e92c172e73118f843c8a61523b7f25c73905a73
45c28f392824e12563ce182c18dcd917674e35af2234b403e68e96b83d83a78e
6f11c5474522dbfefb3cd32e46d4febbd5eff693d0689b0511eedf6d5bc2a3b1
18a45c4f75c74746dc1015d2794843c40ac0f8bca3378645c56522d62a9679a3
88498acddc23aab24b90528c0f4271003eac1a6209416e903fbff552ce02dd7a
c66d9b6891f4dec5130d13037c2e2487e770be71e8e7055ca7402dbb0aae257d
6c5e6e10a95d3cd7666e884f3dc18b81d3f7b6d70fe62b610ae725c8fcffa37c
500ee6bc44e828743938bd47d9fddfd5651cf7d2b5830c4b143cc0ac04f252b7
1b5e939627dcbb2e832296f62f67a163223a56005ed5a24d633c4ccd7d91df05
26bf80e497d822b327d5967ef55a625f932752fe310f3a4bc21a35304acada1c
cc29cb9f1328d6c12ae2b1cb5da94c59d9b4c606baec63d4feb899addafae2ba
de4b529337c9aca6e5a1e7b74de7e010994ce0b58c3fb14ceba0b9b91afcb533
bd7a1946b7861a448232f8d091862386d47a81c2b73d99ce16d027478a99a038
69283fb0f36f12ca6f6f98d5af3743583cff4879d832caeb3fe70258ec27aa77
92c18b79e2ab8c222a614806294b040233568196b98cd722dfe675a91ce11ef9
c607374c38f2cd25ddb6c8ae79a8d47cae7de4ad6f4fec680f8eb3f7096794a2
957962f9146383ffc1a6caf52959dd339f365615ee8a6df875424149247facf0
8ab708c35d01ef1ad53bc193d47a15d8ba6e2ac25e2dbd757e77d88dd8ec6f06
f49bcc859c20c87968335c41adf8cb04c96c3a6182116d16b94b3371e7a54a30
3b4f850a87ab0f70653c12f35a3fa796e4d21db0d900acd29d368af73a6439fd
a0bfd49872e18ecf3f503e27573d10334b2aa4de4ec87c39341ab923f878ea12
bf660952be7efdc0e285d42c6fab666befcd9fc2b173ca195872df5703c045ee
6f4fa2a9e6af18278536fcbb691d4ea53223f217678ce4399a19d63f7c64d694
2ca3ccfe8e1e556556d7c18bb00d300e0b716925afb7f887f5102231f2799846
1983ee20bfec746b6ddbaada4d769622e93dea27690fbdecbced48ce276a499e
bf09312423838afa3f5c5d8bca56604f2700fdb7f4c740ed66aaadf451e04296
7b32efdd3a0ad2c85242b4bc48696e9bfaacccf4b4a3c7fe6bbda9533da076e6
e7561b1b38709d6766f7a62fd56018bee8060fd21c916d7f68b6c8251a8b1f5c
b19b41f8382d6a79c663c58412c7c27f421d940ae898845d73765c18d5cb7860
bfe9103789cedb70d43773329c4a79215decd50595383a0906b1bb689d8ce838
e7c17b370d53b7f36744a32e06d730c4540b86f2525d02f109b33d669ae35843
7e158d4369308bb3a796ccc97d6f1f9e08e0b6fe06a26f58a4451e55dd51ff7e
03976dac8d7d65be94bba35808eccc30417c2afdb5994b19ecea3f7590a068dd
947a43ca6c946efc7c639e059e8cc79b969020e9d90c4bcc6d86ab67b0ac8cae
eadf5da882261e030b8d02393796f6a175975ebd9e770049c7a0c2f9c88f8227
3fc2846fb733d3e866a4d3f51b97252284f85127630db5a0fb0df03c246352ba
ebcd2c3c04d71c76451ff5d0a24e493663767436fea963af0fee93aa12b1392e
c658d0b38d91d5d0389f9550a8fdc2e66173acdd05b4c3eb1dc59f66933c2626
39d8cb9c58530135ae81570e06b28d9f824a7eda95dc52bb7fd2a088836e4aaa
a3faba554b22de53053e74f066f33bfa892e58fbd9e6197d8986c877f754b340
dfed5066ca6d31d0fdab4f3496f73339fa94f1813829c769200975d2556c5516
e69d214c1b2f377dca3043ee9a0650c9e4744d6e82c3b11d83da8b3ec888cec9
b744dc12d59db03513323e1dc27503913cf5e0a8a24e4f2cdd76c0e3cef10bc8
e09f8ad3def56528ddf7555de5a6029243e0fef5ce5e3d764d85e8cc43d50543
5614f236b49730da8b0a119c7fa451990f4b844db07d5fcbc7e32e83e5e045db
a5c18a5a9433dea9e374ac1acfe5ba5fea2496555dc86bf02db637ce76b12992
43efac8ec09da4b10d866d0770df34a96900cf8a7f86895d7baea9dc76230ff3
6e57c6bf6d900ec482f0434370c19cc17aedf1f9f1d50e4e3218b1d3156777a7
c668e59f59b77c6537e6c832a6d25dd2d1d8dfef1a566e2e662937ff40256e65
bca3cab0022837ed31bba0bd1cccd256887b4889a0c7f7ee4ec535a8641b2e12
65f017a6aab4c47e2559ac73f31260b39050014afd52848e2e0ddbb340edae6c
62f498b4aeee228710a5717dae9011b9088328efa207177f2bd062519612528e
238a6b79fb7331fe605afd547ce1474e9e8a589251edec1648c80b8c93fef6d3
70318b34aaa51ec003797400f56c21f36ccac30de05f9da9a4f9a714bda709bb
75ca25384b2cf037b50e8e475adc1d66b61057f96092a2d80facf24a814e5469
5a254102808a5132459c59d1084b7a84d1f76be99e0da4f6aca93892e4273720
17cf3431485e642290cf57948be8e50859867098d6158c8facead5ae89b82d35
85f3a27133e29bcc19cbbd7c270f8beebdd7a6f7a4cd6d85d041f8c94298ed12
ff11523773051a2c0f171a8d95c41c724ea9f45f9d8353d505edcd5fd9642d8d
2f3ee4f6041d823c75f4dca86fe276985482c748ff74c84bfd0b15f27293ffe0
b2f8fe1b5b7e05b152099c24c7d7f3736a4f4d3f587c13890e10b7e94b46d738
d40643e89125622c23797663bb8ed692ac7bf97be653a559c7fdb799d0d8eff5
4f6aa37cc257bd62f4fc4c67e013461531abc8abf1f404996e0c379ede0146ec
5f43eb0a5d711c27c6226a16fa9a6d661e4420f4d257fc82bf8ff660582da380
458d55a7ba7e3bf6558019f8b610fc743799f1e97483519a803afc7d07db3fc7
8236b726edfbb74e52eb0bddea642027248f85f20c582c49823122229f2ff69d
2bec2a0e2daf3dd2679e9b7aeb35ae42185697ea393d09395a5abc324ac3d0f6
77878265cc9bb851383cc75bb15d4035e2ededb8302855b3904061bb482e22c7
71cbd2c7a9356abaf01d9bdcf2c123b8112337a9d44ba682498d644307e64438
1f5c9651b02a7f088801a6b776cec13d89306cfd127cabbaf7a3f316cca8ffb7
61d1af61abcc5d41ee9546916877dd8e3412097047dbdda4802ce9a5904bfab9
3165fbe235e94c9ee7e884e7183889505dc990ae86b2e2eb5d8b4fe8ee782264
53b3a6e2c38be31f6b9a8eb66a5bab4cc88f8e963cc2a56370311ed4ae4e33f4
a62808b86df5280d8694818e96aff3429aaeddb474b680e77ac429fa9d8ed6d0
94267aa25180bb7cd2af1ffab4be9992b6fa5e1372ce329fa5515829a347b435
a4b1f92d274f42766a29e2399cbbc43d8165727b4edcfa5c9bef5badf1af9a5b
2d64747d955545755d09c90301c5d493f3b80fcaba85b2028a73bbe5fd84501f
52ce686734c43428ce8025f6a5df63aedd8b2f3b7a8309561243804cbd046900
fc796d9f32a4a0c75e2d9837af7143f1f2e7a6a048cfb61bcbe0e7f1a489305b
a748c9cf021fe513ce10ca3f09774f22d364fd267db833667a28fed406e727e8
20188c5d6b85a86d60c2e2997fef9ea71ba5fad4d1a21434f5271e9dc1d25786
7a695f459bd51a87477bf8597d6956bb89dc17c9ca9ff2785c875bf33a3a604b
122cd2268d9fac9293118c5f45df161cf8ad087f9c935597e5decde212cee2b3
caafd5ed76fd4a54b31fde7da7a37ad9bce43857a04a5d0cf507d699470890a2
459c94110bf685f3b642bc2dceff08e8d323b228456f8c5b61c77e9950451742
ec37b849818a055def4c354f507a6abc156cf8c163c3986adf9882735768018a
6be284789cba4cb79572d2d2794133f1c28bd64826302b75fddf9755005f339a
cffd2e5fc4d8a62e9b6f33314420fbc963bd0dfc5da9e6f250386f6201dccaa5
c2878f8f78808e3ab606ec22489dee71dcdfad1e56573e6c96bf86b285a3e1e0
d7e500c8b1b710bf14014a2f6dcb205c84760814ff4c0b6ac6fc0d95d2e37fec
947d7e2987034305cbd2e40b9ed3142665795f676d88646324ca5721a189961c
25965bbb449f551869ab124c5e92550dfa6cd0b5a09bd53c061c4f21dd0787ed
2badf5b5b1ee8404c9b139bd446b17f0d3a8ad7700db18bad99a1fc5c88a2589
3682fbe03906800d330390d93a24309f1e15d59f112a39452655bf38662f145c
a08091ba210c710a66ba1e76c135991b7c11e074245fdf7141986e277308bc40
1eed7462ac6861ef0c1f47e1f2c9451d4b077bb17cdf31c309dfbe0c4db2d75c
50483fa70c402cbca10fbe9bffeadf92038cd732893d954da027cca5b4086433
f7c1c7356a1e4a890d63555f7b8f64ee624eefaacde7dc5bc6ac2f05eca4dd48
08c15349ace3a1166d1c718269617cc9adbad9cd624b955cef725d07216c9609
ac70f55e10851c193768e0b7b0857be9b1e8a5143c8f9c61450b999aba3f623a
bf3db9c1a87e5b1ae8edf4266b1e1e0747abb2ee91eb245d94ffce4c0cd6f90b
51bff8ba6e169820cd530596d7666735b5338e62cd412881d235455eba0e2b24
16cdcbe551a4112baea5e49b4717e79c1ba269910f9681825e575fd5e9ebeb48
e30431341cc2971dde163e5125a0f7dca6243182ae7d8d994bc62e486c6820df
ed387c95175a8e053e6c405d46be939888f25b5df1a0689a185bc685c0ca1341
d4f58df4af545c049858ebbcdcdba0611e5d3c23a2a9bdc6a9dbaf2efdc145ca
9aa1a2353294f226d41be2d012183332a85a973ca6f2ef84d41672d23456ab6a
0ea7dab3dad9a232eabf0fd5df97da1b1c253238d3f63462bff1085225553329
b7e83ce4d88ee43eba1e1ec3735b85c73827618efd753d4a3f69630ab2098f0b
3dc18f6432535eadcd8460e2a3e1b570ff36a508237f4641a11151ed6a25a236
f1c46fbf2cdb30d84aa22acc95d471fe43ecab6f54944166a140cb3e852957ec
4b4646e06ecd5ddd395f8ab5590cff235a7c4318d9f5c6ca2032b12de3283255
be329b882ff64352f3efb86e5e73c4e5549479c00ea61894f1db02505050d378
3b006062ce0ecdd0134dab3d2556cc2ed78d5278a6fc08ab999f01bb3c31d252
85b119d831088dcbd474aab73d77412717f198435492aa08bfb72b870076f366
49c6bf28a0454cfd07b18806eae3fc2600cdf7b0e2a1ac6604e489f4dbf83b34
97806e3234dbe9d43838f555f19d40c1632901964d72d76dc4e2ded669bcdafc
ce6a886347cb72af861f07c8e1f201efd2c59529ffeca87cf4f2c66b15560271
fc01981f54374c0629888b5280ecb175978ebba6c16256042a947eef99114020
3ed96c9229b053414b117e1d5d8ede9824fe195dcc59369e26d547a7336ca792
a4951c6f05ca60b4e79ba4c41977c433b74b612027ef2699cbb472a32e284181
95670ef0966d7b3b773a7d019c9446b833418f0b0fd8ac876bbe0fd1459d4e8a
e0f48ceb39c8a071492b0385dc2d81060d640a490e4886190334a66d7a1fd6cf
2de4ec6543cb3c36d0cb9f5dc94476084aa45e43d36979f390ab19c1a17b3710
cfc9ca96ecfca25df6b4675c358840f9c2438e952ba4c297c031157dcccbab77
931e672d032b154487493d48115914e4b3cac92d36ea3f9479befa66f6445c4e
0ac194b017aedf31f9abc1bf461f440aed0ea9d70804b4d415963a7aeb5d6dcd
469cd45d1a04df485c9c5096ef2cbec24f015e1689e9e7df789f59df4dfd7e25
d80fdc9d9ea31b0eeaa1bcc455199a640ffe2196ca4f0c73f41bf7d2fa3c594c
d42300d38ce4032fa0a1b50c58c0fa2a5e6c0bf3aa202af8788902c8bc9fc92c
a46d3a64ba0ee3de2cb98355482122423207e64458d8754cbf85197bca4e1206
5db644c0c4537c276eb18644e1d4d97e978868b144853c9301627bb578d648b7
88019cc37f90b9a5fe10a325eebeaac2d105982119a6db47709ef5330a91b078
b908830841025bb855629de3e6829e3d66a88813f49b085d8007ae69f89012b0
568ad64bef7c583698b98e9fe24934943fe71fe38d9eafa505c751a1076a0060
f26a46f9e02ae45bcd778771176378e6ea4c1fd238b6812e9ef3c3ead36fb051
a659a75004a5e106e3354c3f091e149f5055110118d2fadf256a26664be6ec5c
9618a20cf013c1d817935af2c8bc45e8ad8c9f0bff98790a123e2e5bc3a3ce26
2b40d93a62069e01874835cca75c4a18142a8452ed02ca3ad6261cebf2ee3912
190172b4647f7a4d08486967e88498f58f05debe61a9d1c31cc81029a241407d
f264e0ba53b8c4a5ee794fa32a2c52989b102fea7f14fcd42ab75348113d6caa
fe748b44b7b04fea143970828c624a5d308a1b08c5e21f5c0bad41daf700fb15
b6c6d0222703957d7cfba9c9f2f4c4132da9341a688877cafd8552a31c322698
fe509b1c42cfa85b97e8d2903f68698b2dd551dc5422bfcf0ea7242ceb2a57ba
be4b6aac4d4ff5b9c85177631455a46585e421b9ffb407f0f943c9c7ac6bea3c
85173cd4ccef5de3322dfdd8029975a16dc9053bbf6a06f1c96e62055e3f2e43
98e031e88783f11c91e0834509b3172b40c4a9e74e200b1ef052be0cb3996e12
ae58176f0d5ce9f5498c1603fc9e2498955b974d0ddbd843c9f1c6d7321ba8fa
4a1be0d981ce91e643d35f573dbb704276dbf18c9b8fc29c7ba93a937bd1e93a
e58ec417b5fff41e5f1d2df7051bd3a12293e9c3dbfc52a4a13b3b49cc622596
94ac3b7cad1f061378775b92d095715d9db05bd823d90a52329e0206adcde607
5de3cf48552c1a6c51d68fe133bb3178fa8337b33ce3368416795e6b595c2668
7a80a22c257f1b5070a49552aa4bd52a62769811316bf5a76e3b729818e6d130
c85f8cd055bb5c19b35a83728aedb363dd1f2aba870a00798991b4fa97870061
4145c1920e214b787c7adbc23568cbc73401d176960e13cbccc5b5c31b37cce4
ba34998e7cf1c415850d9360893bfec0100203b56ea5169c8d1d9bc7f54af568
0d897530df0a95022744a96c152681c19505c01db05a4dcca720af3f3b8e0bcd
8c995fda227360cf7dfda437695547acd54592a42b21187abab355dfd13337e6
ade2148027e9a8906d1c139c48c1d7942f84b190a30db3d343fcb2e2dee19a7d
72dcdab82b60180c5ec131a3b7a987010dcf88880e51f0816b35411d1ec8cf9d
5d30ba2570eb86b9dcd3067e5038a3624372ba7f519acd121a957ec1ed3be91b
3e0af3497217a72ed2448e74c506c024ac823e9240c3cc6b24494058ce6d5a7f
1b49dba7585c0ca6d7ad87211755a8a02e84a31fc62a76f9867578d1216967e9
f9736f4cd04380609771e76857b56966e8b0685aa4e3bbc4ca385706fd42c326
f8278dd0152f7425435ea0c31358f804e344b49cc2c2c265edb955e1e243a719
af79a012b28cdb932738bcf4141e83d785075da4967c380fa98d584609900649
3a59755afad73306e3d1b11254d1cf2f7d8d8991562815747d3b00f0c99b06f4
a444dd518e59fae90a0e076ff5199ccbd4f27f0279e5be6fd3db7857e242c216
31250c93d1b46a661cba290c9850c30ebfefa0c761f3e26060df83c70b04e4c2
afc1dd96ead61518816f41e2aa957f49fc72605bc51508a19712df8209c2f721
35d0ba5a06537dd9a86bf74b1a89c8e182fe165dd42f920a2a0b13dcbd926f61
d9b4680d364e43b9cc51c9e5bba59f71beb2e37895e3d0223d6320e9b21a2508
5d3e153381d5fd42f9fda71e1fb91b2af733898b15dfaf9bdcce2668ecacaeff
c3bd0c52193e8d4dd77dfa27a2110dee7323ea1afd7c210c767329bdef7f9ab1
e4aa8eee35b9d7c9d0c9b92d9cbcee13e5de0bd0fcc3ed476ee9f03fdea97483
6212a2d4909f4e5c35a3bd4960fd5a286d7f806b118981b703b86a2d7cb2cdd1
40cc7957677e0154d061a37797e3e18e1843e4b0eeeddc7675801eacebd3674c
a8e9304b1698d0efdeb4956eac9bca766cd597379e187ad305d830f3b41558a4
dead3b3c97bb020fbed2e29e82e36d9b2ee33d31fd2cfcb872d274b718460d5c
ca37fa017cae93bcabe70b1b069cf149d8296b943d4c000a866cd30049bd7d07
59674a559020388a486c54d06509ea68ccd4efb90b3a7b1a2a4fb991d71a571d
c7acd10e945ed65d4f01036a0f74648eb1b8a2a0338f0582f538dad94f8cfaf3
654bac0185d42b720235ee546aa57e45d3019482f710a9d315f595f4e62cb2a5
f23c962102f326b92b91b5c1df661931f84051e673ef77d9959f6face9ba3125
35debf70a845be573876135ad37ede8604f737e27f23a9d0a4eaa6faeab12d7a
f3abadecbb13d480c20ffa912f6a8f45877a094c8d1bab36063a24705d651277
448b9f2f9662bacc2a2e3487c109e925ddff1e323cdadf7ee1368518c09a4ecd
5a2a7ab958b49adfd1b128d8d1cd442776a936a426cc7caa135052811fd0315c
988fc609ccd5a3a1d99c32646d8a981ab70491fb3322c31f43c110fd102cb525
336156ab2e29ae77c4dadf1b2ca1e1059c92a94b93cc36794502bb92ce0b8b1c
5a9ff4d1058c7094f09c7cf74806cbadd0e49028f99cb598a80b2ec57093fd4b
e65a8351ab61322231cc8cd5c6573b127dd9d28390a15cc7dfdc977b3fa23771
c050843afc8253eb9f0abe24f95f60076a07b36354b4060abf31efa42c3aad79
da668f25138e08f2b71ffacdfabb4315d9b09728518b069e58ef4db925e5befd
ee556e364dac0e7c1da563aa371e3ff1a66fa7c042cf6640ab5ed3516e775cbc
3884e384beb449dd89e83ebc5fa85af82b82bb1dadc84e5240412b32c1efda9b
4a1498dcf7f9802bc79d614e2fd1d5622c937e6b2cc67267e42695510d64550f
b484068ccf97aba44f89c39b264ca7fdfb90a8bde4a3f3e4d6193d6345241ebc
b69758d76f2265865e165f36bd3036a2ef8b1076e9973a446f1e8d4c63938221
64e32c502274c827b2a852d2ade0cf8edc754ec74e0ee5b03da5a33a3fbbe698
4fdc13c9dafe50fc7eaee0842b4a4db670ecc71f2d6466bf887238aae352b233
a51111df3ff037d71e97bea028d4a977a8f6d2292c7e028bc57a4ed8c1e3cebb
e37b50e2c60bfd20b41c338f562630be733dae05ec91d1c6efb8356dda119307
089d15d3b162bc0cdb0f744ec4010858c609a665b843aa526f404d13b50df2f2
675f5afcba01e8ecaadf8be9e0f628043e4256098528d4f91447c4c279fc1099
ef9ea8bc0b2fe3fcf751a4d0e344b5b5d5309cc856d9941ddc49cafd5e853c0d
506fac61f3544583fbee461b35f6d16c17609d3c47b1b4f83cec48cb86a3dc26
546198cff92ec3ebb643204dc16022e30fc65eb5ccfdf0fed373ff09aaecb85d
09d646d2e493555b0e025f0f8c0f1589ace87d021b3179143057212289c2afb1
739b8637515d809b7d8f0532278a4b0ae0cf650e7dc9752346412b8787a8ca0b
6d38b50953f43053f518b80751fd2f74169a3162b41e3f3ffd1709ced5b6842c
08edc02e97ab605e376fd8b4d9f151755b5c7895edfe87fa921fb79c1ef903b1
b7d6306d9ad5651f1bfa727f0af45c0308fcbb0d75faa27a634667bb73a24f4b
275ac6ab65b409241823ed26f54b58ede11783b746e586ca68b2b7618eae9158
98e4b8603cdfb24a233c5c46f3d88ed5ce9a2f021190e2ada13dabc9324aaa43
8432ffffe8f7e68f5735991e6c96148dd3b86a68443d6b968c3cdcec3e2d193b
d30fe0e825644d66a5f431bad6f4a5a4ea31551f582090d71a531766f059ae9d
db3ebcc42bda4aaf20bac271b90d38df4b568da34bcc6c15e80b5af3796ec8cf
f155e70a9fd45cfbae4dd746453fc337f07f9efb62b57626dd5b92b85688b82d
be6ff963d0c61163331ccd8a678c444515dea0bb00d81b06fb08f804bca3d291
4efb666a06b8f52dde7d0dd5cf2cb546eb721cc0d08cb6d39de906fe1fef872a
5a65715ccb5190f2ef563029d8b66943611256927db602b90242a7d8fc3d05c1
2b0b8d821fe6c07254580d2abffa360f1651ae85ed9cfe061ab2cfe1173cedfb
507ae2b35bd83711df0269b44b2c1cb5d8263e8e485c119b20aa9eedeed41013
5d2e8181ad33aff18655842819b0c2d156d19f324b5074a7d9450d0dc2b75b04
7303ebe4f635bf11208cbfee0fabca2fe5c30a061b286f5a7a93211c7afdb3c3
5e3f4d682fb67e548598008abe1b93d30f4ff9dd91579384053097b03f459325
75d649e1a0f4bd5980bf2d0f8bc32665f7ba80686c8c0e11d2ebf7a577a1f920
a9550e7df6671ce7012db1710a8b92af4f7551abb0932b22f847f81e6113c942
21a2961a247914b02adb9fe0669264faa134f6b232d1e8361dfdb91021733f4e
90bb64d8c0aaa01ec86d03558741e77ef289393d105748d1c46c932e86a5f854
7c8500b693f37af040d836fcf400590ebaf3a50eab2ce175beb15ee50f38b905
49a088bc87279c86abdb5a5089f2feb57947ba13df7febd5ce0bfde99a813691
37c636a83acc1cb423398068878f6c1f833262708d83a4ec4e244c45b872dc11
6b6c164c638766d71d6f41942091d85de3024c883f17a4274a01362ba835635a
415347c18ab934d7c1ea2c25cd5c9f2a5fe676f04d6d433b67064cc3829392b8
fe5028fcf828f95a62842ba3c8937a619721369b50b4ee2426715742f1d63969
d08d5060adc20379cc363a2edec224803617cce8212f6a172a41052cdb26e527
99798738c0812f39e7f4bdd21c7c6c4e7b5021e1b4ca630d50493ff89a6e1561
d51539c86692a2ea0c6c8ad8fbf8262c15a544ee7e9907fc1f69e99ddc89af7c
4461d1d57c8f2a65fe7eb38f5e1d2677aba4f1f2392401767dc3701f315c2223
20f8b1be589e1a02adfcdf3e530a67305e5b131229bfefe2c98d5f75f08fd234
b032a4c721d11bfa17fbb322518364aefee830b66768f078dc5fd237093d7780
06a3bd70624d272d0888ad27e468defb536b554b0f42dba66a82db06f936be6a
49e0ba24989688e68db88ed1007cb46f33322e887755778e42591a84d25b0004
41a82b9d54e170973fdc168e42709cb2f10944414c9405e529c9448294268ccb
94a73c65585d3ac343b8ae0010ddbbf90f00eff5d0d656acac63368c9c9f7e8f
07f892b5c481e22c6a2391d92b4c127d5dcd9a725f30d21faaf0c397ee7b6a83
222a119cf3c42075533fb9aeaca741630cba799858e60778142e3a098a685b95";
            #endregion


            //Verify rng.Next();
            correctResult1 = correctResult1.Replace("\r\n", "");
            correctResult2 = correctResult2.Replace("\r\n", "");

            StringBuilder result = new StringBuilder();

            CryptRand rng = CryptRand.Instance;
            rng.PrepareUnitTesting1();

            for (int i = 0; i < 2; ++i)
                for (int j = 0; j < 256; ++j)
                    result.Append(String.Format("{0:x8}", rng.Next()));

            Assert.AreEqual(result.ToString(), correctResult1, "Error in methode Next");


            //Verify rng.NextByte();
            result = new StringBuilder();
            rng.PrepareUnitTesting1();

            for (int i = 0; i < 2; ++i)
                for (int j = 0; j < 256; ++j)
                    for (int k = 0; k < 4; ++k)
                        result.Append(String.Format("{0:x2}", rng.NextByte()));

            Assert.AreEqual(result.ToString(), correctResult1, "Error in methode NextByte");


            //Verify RandInit();
            string tmp = "";
            result = new StringBuilder();
            rng.PrepareUnitTesting2();

            for (int i = 0; i < 10; ++i)
            {
                tmp = "";
                for (int j = 0; j < 256; ++j)
                    tmp = String.Format("{0:x8}", rng.Next()) + tmp;

                result.Append(tmp);
            }

            int len1 = result.Length;
            int len2 = correctResult2.Length;

            Assert.AreEqual(result.ToString(), correctResult2, "Error in methode RandInit");


            
        }

        
        public void CryptRandTestSetUp()
        {
            //20 000 bits
            sample = new byte[2500];
            rand.GetBytes(sample);
        }

        // count the number of 1
       
        public void CryptRandMonobit()
        {
            int x = 0;
            for (int i = 0; i < sample.Length; i++)
            {
                byte b = sample[i];
                for (int j = 0; j < 8; j++)
                {
                    if ((b & 0x01) == 0x01)
                        x++;
                    // next bit
                    b >>= 1;
                }
            }
            Assert.IsTrue((9725 < x), String.Format("Monobit x={0} > 9725", x));
            Assert.IsTrue((x < 10275), String.Format("Monobit x={0} < 10275", x));
        }

        // 16 patterns (nibbles)
        
        public void CryptRandPoker()
        {
            int[] pattern = new int[16];
            for (int i = 0; i < sample.Length; i++)
            {
                byte b = sample[i];
                int n = (b & 0x0F);
                pattern[n]++;
                b >>= 4;
                n = b;
                pattern[n]++;
            }
            double result = 0;
            for (int i = 0; i < 16; i++)
                result += (pattern[i] * pattern[i]);
            result = ((16 * result) / 5000) - 5000;

            Assert.IsTrue(((result > 2.16) && (result < 46.17)), " Poker: " + result);
        }

        // runs of 1 (or 0)
       
        public void CryptRandRuns()
        {
            int[,] runs = new int[6, 2];
            int x = 0;
            bool one = false;
            bool zero = false;
            for (int i = sample.Length - 1; i >= 0; i--)
            {
                byte b = sample[i];
                for (int j = 0; j < 8; j++)
                {
                    if ((b & 0x01) == 0x01)
                    {
                        if (!one)
                        {
                            one = true;
                            zero = false;
                            int p = Math.Min(x, 6) - 1;
                            if (p >= 0)
                                runs[p, 0]++;
                            x = 0;
                        }
                    }
                    else
                    {
                        if (!zero)
                        {
                            one = false;
                            zero = true;
                            int p = Math.Min(x, 6) - 1;
                            if (p >= 0)
                                runs[p, 1]++;
                            x = 0;
                        }
                    }
                    x++;
                    // next bit
                    b >>= 1;
                }
            }
            // don't forget the ast run
            if (x > 0)
            {
                int p = Math.Min(x, 6) - 1;
                if (p >= 0)
                    runs[p, zero ? 0 : 1]++;
            }
            // Updated ranges as per FIPS140-2 Change Notice #1
            // check for runs of zeros
            Assert.IsTrue(((runs[0, 0] >= 2315) && (runs[0, 0] <= 2685)), " 0-Runs length=1: " + runs[0, 0]);
            Assert.IsTrue(((runs[1, 0] >= 1114) && (runs[1, 0] <= 1386)), " 0-Runs length=2: " + runs[1, 0]);
            Assert.IsTrue(((runs[2, 0] >= 527) && (runs[2, 0] <= 723)),  " 0-Runs length=3: " + runs[2, 0]);
            Assert.IsTrue(((runs[3, 0] >= 240) && (runs[3, 0] <= 384)),  " 0-Runs length=4: " + runs[3, 0]);
            Assert.IsTrue(((runs[4, 0] >= 103) && (runs[4, 0] <= 209)),  " 0-Runs length=5: " + runs[4, 0]);
            Assert.IsTrue(((runs[5, 0] >= 103) && (runs[5, 0] <= 209)),  " 0-Runs length=6+ " + runs[5, 0]);
            // check for runs of ones
            Assert.IsTrue(((runs[0, 1] >= 2315) && (runs[0, 1] <= 2685)),  " 1-Runs length=1: " + runs[0, 1]);
            Assert.IsTrue(((runs[1, 1] >= 1114) && (runs[1, 1] <= 1386)),  " 1-Runs length=2: " + runs[1, 1]);
            Assert.IsTrue(((runs[2, 1] >= 527) && (runs[2, 1] <= 723)),  " 1-Runs length=3: " + runs[2, 1]);
            Assert.IsTrue(((runs[3, 1] >= 240) && (runs[3, 1] <= 384)),  " 1-Runs length=4: " + runs[3, 1]);
            Assert.IsTrue(((runs[4, 1] >= 103) && (runs[4, 1] <= 209)),  " 1-Runs length=5: " + runs[4, 1]);
            Assert.IsTrue(((runs[5, 1] >= 103) && (runs[5, 1] <= 209)),  " 1-Runs length=6+ " + runs[5, 1]);
        }

        // no long runs of 26 or more (0 or 1)
       
        public void CryptRandLongRuns()
        {
            int longestRun = 0;
            int currentRun = 0;
            bool one = false;
            bool zero = false;
            for (int i = sample.Length - 1; i >= 0; i--)
            {
                byte b = sample[i];
                for (int j = 0; j < 8; j++)
                {
                    if ((b & 0x01) == 0x01)
                    {
                        if (!one)
                        {
                            one = true;
                            zero = false;
                            longestRun = Math.Max(longestRun, currentRun);
                            currentRun = 0;
                        }
                        currentRun++;
                    }
                    else
                    {
                        if (!zero)
                        {
                            one = false;
                            zero = true;
                            longestRun = Math.Max(longestRun, currentRun);
                            currentRun = 0;
                        }
                        currentRun++;
                    }
                    // next bit
                    b >>= 1;
                }
            }
            Assert.IsTrue((longestRun < 26), " Long Runs max = " + longestRun);
        }

        #endregion

#region Symmetric Algorithm Tests

#region AESFinalists
        [Test]

#region  Rijndael
        public void RijndaelTest()
        {
            RijndaelOpen aes = new RijndaelOpen();           
            aes.Padding = PaddingMode.None;
            aes.Mode = CipherMode.ECB;
         
            
            RijndaelTransform encrypt, decrypt;

            //Testvectors  
            byte[] input = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };            

            //128 Bit
            byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };            
            byte[] cipher = new byte[16];
            byte[] decipher = new byte[16];
            byte[] correctResult = new byte[] { 0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0xF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A };

            encrypt = new RijndaelTransform(aes, true, key, null);
            decrypt = new RijndaelTransform(aes, false, key, null);

            encrypt.TransformBlock(input, 0, input.Length, cipher, 0);
            decrypt.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Encrypt: 128bit");
            Assert.AreEqual(decipher, input, "Decrypt: 128bit");

            //192 Bit
            aes.KeySize = 192;
            aes.BlockSize = 128;
      

            key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
            cipher = new byte[input.Length];
            decipher = new byte[input.Length];
            correctResult = new byte[] { 0x00, 0x60, 0xBF, 0xFE, 0x46, 0x83, 0x4B, 0xB8, 0xDA, 0x5C, 0xF9, 0xA6, 0x1F, 0xF2, 0x20, 0xAE };

            encrypt = new RijndaelTransform(aes, true, key, null);
            decrypt = new RijndaelTransform(aes, false, key, null);

            encrypt.TransformBlock(input, 0, input.Length, cipher, 0);
            decrypt.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Encrypt: 192 bit");
            Assert.AreEqual(decipher, input, "Decrypt: 192 bit");

            //256 Bit
            aes.KeySize = 256;
            aes.BlockSize = 128;


            key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
            cipher = new byte[input.Length];
            decipher = new byte[input.Length];
            correctResult = new byte[] { 0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96, 0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92 };

            encrypt = new RijndaelTransform(aes, true, key, null);
            decrypt = new RijndaelTransform(aes, false, key, null);

            encrypt.TransformBlock(input, 0, input.Length, cipher, 0);
            decrypt.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Encrypt: 256 bit");
            Assert.AreEqual(decipher, input, "Decrypt: 256 bit");


        }
        #endregion

#region Twofish
        [Test]
        public void TwofishTest()
        {

            Twofish algo = new Twofish();
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;

            TwofishTransform twofish;
            

            byte[] key, plain, cipher, decipher, correctResult;

            //128 Bit
            key = new byte[16]; 
            plain = new byte[16];
            cipher = new byte[16];
            decipher = new byte[16] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            correctResult = GetBytes("9F589F5CF6122C32B6BFEC2F2AE8C35A");

            twofish = new TwofishTransform(algo, true, key, null);
            twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt

            twofish = new TwofishTransform(algo, false, key, null);
            twofish.TransformBlock(cipher, 0, cipher.Length, decipher, 0); //Decrypt


            Assert.AreEqual(cipher, correctResult); //Cipher is ok
            Assert.AreEqual(decipher, plain); //Decipher is ok

            //192 Bit
            key = GetBytes("0123456789ABCDEFFEDCBA98765432100011223344556677");            
            plain = new byte[16];
            cipher = new byte[16];
            correctResult = GetBytes("CFD1D2E5A9BE9CDF501F13B892BD2248");
            CryptRand.Instance.GetBytes(decipher);


            twofish = new TwofishTransform(algo, true, key, null);
            twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt

            twofish = new TwofishTransform(algo, false, key, null);
            twofish.TransformBlock(cipher, 0, cipher.Length, decipher, 0); //Decrypt                      

            Assert.AreEqual(cipher, correctResult);
            Assert.AreEqual(decipher, plain);


            //256 Bit
            key = GetBytes("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF");        
            plain = new byte[16];
            cipher = new byte[16];
            correctResult = GetBytes("37527BE0052334B89F0CFCCAE87CFA20");
            CryptRand.Instance.GetBytes(decipher);

            twofish = new TwofishTransform(algo, true, key, null);
            twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt

            twofish = new TwofishTransform(algo, false, key, null);
            twofish.TransformBlock(cipher, 0, cipher.Length, decipher, 0); //Decrypt      

            Assert.AreEqual(cipher, correctResult); 
            Assert.AreEqual(decipher, plain); 



            //Tables Known Answer Test (ecb_tbl.txt)
            //128 Bit
            key = new byte[16];
            plain = new byte[16];
            cipher = new byte[16];
            correctResult = GetBytes("5D9D4EEFFA9151575524F115815A12E0");
            

            for (int i = 0; i < 49; i++)
            {
                twofish = new TwofishTransform(algo, true, key, null);
                twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt                

                key = (byte[])plain.Clone();               
                plain = (byte[])cipher.Clone();
            }

            Assert.AreEqual(cipher, correctResult);

            //192 Bit
            key = new byte[24];
            plain = new byte[16];
            cipher = new byte[16];
            correctResult = GetBytes("E75449212BEEF9F4A390BD860A640941");
            

            for (int i = 0; i < 49; i++)
            {
                twofish = new TwofishTransform(algo, true, key, null);
                twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt   

                Buffer.BlockCopy(key, 0, key, 16, 8);
                Buffer.BlockCopy(plain, 0, key, 0, plain.Length);               
                Buffer.BlockCopy(cipher, 0, plain, 0, cipher.Length);
            }

            Assert.AreEqual(cipher, correctResult);

            //256 Bit
            key = new byte[32];
            plain = new byte[16];
            cipher = new byte[16];
            correctResult = GetBytes("37FE26FF1CF66175F5DDF4C33B97A205");
            

            for (int i = 0; i < 49; i++)
            {
                twofish = new TwofishTransform(algo, true, key, null);
                twofish.TransformBlock(plain, 0, plain.Length, cipher, 0); //Encrypt   

                Buffer.BlockCopy(key, 0, key, 16, 16);
                Buffer.BlockCopy(plain, 0, key, 0, plain.Length);              
                Buffer.BlockCopy(cipher, 0, plain, 0, cipher.Length);
            }

            Assert.AreEqual(cipher, correctResult);

            /* Test: Decryption */
            //Test decryption with 128, 192 and 256 bit keys
            for (int keyBytes = 16; keyBytes <= 32; keyBytes += 8)
            {
                //Encrypt and decrypt 256 random values with random keys
                for (int i = 0; i < 256; i++)
                {
                    key = new byte[keyBytes];
                    plain = new byte[16];
                    cipher = new byte[16];
                    decipher = new byte[16];

                    //Random key and random plaintext
                    CryptRand.Instance.GetBytes(key);
                    CryptRand.Instance.GetBytes(plain);

                    //Encrypt
                    twofish = new TwofishTransform(algo, true, key, null);
                    twofish.TransformBlock(plain, 0, plain.Length, cipher, 0);

                    //Decrypt
                    twofish = new TwofishTransform(algo, false, key, null);
                    twofish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

                    Assert.AreEqual(plain, decipher, "Error in decryption");
                }
            }


        }
      
       
        #endregion

#region Serpent
        [Test]
        public void SerpentTest()
        {
            Serpent algo = new Serpent();
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;

            SerpentTransform serpent;
            

            byte[] key, plain, cipher, decipher, correctResult, tmp;



            /* Test: Encryption */

            //File: 'ecb_e_m.txt' / Monte Carlo Test Encryption
            //Test just until I=50 (performance reasons)
            //128 Bit
            key = new byte[16];
            plain = new byte[16];
            correctResult = GetBytes("62f0ad9d5fe4cbbbc151c8cbf765d822"); //I=50    

            for (int i = 0; i <= 50; i++)
            {
                serpent = new SerpentTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                    serpent.TransformBlock(plain, 0, plain.Length, plain, 0);                    

                for (int k = 0; k < key.Length; k++)
                    key[k] ^= plain[k];
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 128 bit key");


            //192 Bit
            key = new byte[24];
            plain = new byte[16];
            tmp = new byte[16];
            correctResult = GetBytes("c68e22f403dd3aa990275c7c7bb7dc3d"); //I=50  

            for (int i = 0; i <= 50; i++)
            {
                serpent = new SerpentTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                {
                    serpent.TransformBlock(plain, 0, plain.Length, plain, 0);

                    if (j == 9998)
                        Buffer.BlockCopy(plain, 0, tmp, 0, plain.Length);
                }

                for (int k = 0; k < key.Length; k++)
                {
                    if (k < plain.Length)
                        key[k] ^= plain[k];
                    else
                        key[k] ^= tmp[k - 16];
                }
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 192 bit key");


            //256 Bit
            key = new byte[32];
            plain = new byte[16];
            tmp = new byte[16];

            correctResult = GetBytes("3ee41f4b2e79b3b84c917c96dca4a3b5"); //I=50  

            for (int i = 0; i <= 50; i++)
            {
                serpent = new SerpentTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                {
                    serpent.TransformBlock(plain, 0, plain.Length, plain, 0);

                    if (j == 9998)
                        Buffer.BlockCopy(plain, 0, tmp, 0, plain.Length);
                }

                for (int k = 0; k < key.Length; k++)
                {
                    if (k < plain.Length)
                        key[k] ^= plain[k];
                    else
                        key[k] ^= tmp[k - 16];
                }
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 256 bit key");


            /* Test: Decryption */
            //Test decryption with 128, 192 and 256 bit keys
            for (int keyBytes = 16; keyBytes <= 32; keyBytes += 8)
            {
                //Encrypt and decrypt 256 random values with random keys
                for (int i = 0; i < 256; i++)
                {
                    key = new byte[keyBytes];
                    plain = new byte[16];
                    cipher = new byte[16];
                    decipher = new byte[16];

                    //Random key and random plaintext
                    CryptRand.Instance.GetBytes(key);
                    CryptRand.Instance.GetBytes(plain);

                    //Encrypt
                    serpent = new SerpentTransform(algo, true, key, null);
                    serpent.TransformBlock(plain, 0, plain.Length, cipher, 0);

                    //Decrypt
                    serpent = new SerpentTransform(algo, false, key, null);
                    serpent.TransformBlock(cipher, 0, cipher.Length, decipher, 0);                  

                    Assert.AreEqual(plain, decipher, "Error in decryption");
                }
            }
        }
        #endregion

#region MARS
        [Test]
        public void MarsTest()
        {
            Mars algo = new Mars();
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;

            MarsTransform mars;

            byte[] key, plain, cipher, decipher, correctResult, tmp;

            //File: 'ecb_tbl.txt'
            //Test encryption

            //128 Bit
            key = new byte[16];
            plain = new byte[16];
            correctResult = GetBytes("9213B43D06D0AB7ECCC5CA751C5DBAA8");
            mars = new MarsTransform(algo, true, key, null);


            for (int i = 0; i < 40; i++)
                mars.TransformBlock(plain, 0, plain.Length, plain, 0);                

            Assert.AreEqual(plain, correctResult, "Error in encryption with 128 bit key");

            //192 Bit
            key = new byte[24];
            plain = GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            correctResult = GetBytes("6E76BEF9304B115EFC1C9002FBB848A0");
            mars = new MarsTransform(algo, true, key, null);

            for (int i = 0; i < 40; i++)
                mars.TransformBlock(plain, 0, plain.Length, plain, 0); 

            Assert.AreEqual(plain, correctResult, "Error in encryption with 192 bit key");

            //256 Bit
            key = new byte[32];
            plain = GetBytes("62E45B4CF3477F1DD65063729D9ABA8F");
            correctResult = GetBytes("9A1C14309E4B246C9E7B485A7F41D046");
            mars = new MarsTransform(algo, true, key, null);

            for (int i = 0; i < 40; i++)
                mars.TransformBlock(plain, 0, plain.Length, plain, 0); 

            Assert.AreEqual(plain, correctResult, "Error in encryption with 256 bit key");


            /****************************/

            //File: ecb_e_m.txt
            //Monte Carlo Test Encryption
            //Test just until I=50 (performance reasons)
            //128 bit
            key = new byte[16];
            plain = new byte[16];
            correctResult = GetBytes("F7A6210C39A62B0A42DC8F1807E03CF1"); //I=50    

            for (int i = 0; i <= 50; i++)
            {
                mars = new MarsTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                    mars.TransformBlock(plain, 0, plain.Length, plain, 0); 

                for (int k = 0; k < key.Length; k++)
                    key[k] ^= plain[k];
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 128 bit key");


            //192 bit
            key = new byte[24];
            plain = new byte[16];
            tmp = new byte[16];
            correctResult = GetBytes("3C94EF1BD1549A0A64E81BE7176534DE"); //I=50  

            for (int i = 0; i <= 50; i++)
            {
                mars = new MarsTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                {
                    mars.TransformBlock(plain, 0, plain.Length, plain, 0); 

                    if (j == 9998)
                        Buffer.BlockCopy(plain, 0, tmp, 0, plain.Length);
                }

                for (int k = 0; k < key.Length; k++)
                {
                    if (k < 8)
                        key[k] ^= tmp[k + 8];
                    else
                        key[k] ^= plain[k - 8];
                }
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 192 bit key");

            //256 bit
            key = new byte[32];
            plain = new byte[16];
            tmp = new byte[16];
            correctResult = GetBytes("03541F854CB021848BABCC711B9727BE"); //I=50  

            for (int i = 0; i <= 50; i++)
            {
                mars = new MarsTransform(algo, true, key, null);

                for (int j = 0; j < 10000; j++)
                {
                    mars.TransformBlock(plain, 0, plain.Length, plain, 0); 

                    if (j == 9998)
                        Buffer.BlockCopy(plain, 0, tmp, 0, plain.Length);
                }

                for (int k = 0; k < key.Length; k++)
                {
                    if (k < 16)
                        key[k] ^= tmp[k];
                    else
                        key[k] ^= plain[k - 16];
                }
            }

            Assert.AreEqual(plain, correctResult, "Error Encryption: 256 bit key");


            /*******************/

            /* Test: Decryption */
            //Test decryption with 128, 192 and 256 bit keys
            for (int keyBytes = 16; keyBytes <= 32; keyBytes += 8)
            {
                //Encrypt and decrypt 256 random values with random keys
                for (int i = 0; i < 256; i++)
                {
                    key = new byte[keyBytes];
                    plain = new byte[16];
                    cipher = new byte[16];
                    decipher = new byte[16];

                    //Random key and random plaintext
                    CryptRand.Instance.GetBytes(key);
                    CryptRand.Instance.GetBytes(plain);

                    //Encrypt
                    mars = new MarsTransform(algo, true, key, null);
                    mars.TransformBlock(plain, 0, plain.Length, cipher, 0);
                   

                    //Decrypt
                    mars = new MarsTransform(algo, false, key, null);
                    mars.TransformBlock(cipher, 0, cipher.Length, decipher, 0);
                    

                    Assert.AreEqual(plain, decipher, "Error in decryption");
                }
            }

        }
        #endregion

        #endregion

#region Blowfish
        [Test]
        public void BlowfishTest()
        {
            MemoryStream stream = new MemoryStream();
            Blowfish algo = new Blowfish();
            BlowfishTransform blowfish;
            byte[] key;

            algo.Mode = CipherMode.ECB;
            algo.Key = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            algo.Padding = PaddingMode.None;


            byte[] plain;
            byte[] correctResult;
            byte[] cipher = new byte[algo.BlockSize>>3];
            byte[] decipher = new byte[algo.BlockSize>>3];





            //Some testvectors
            key = GetBytes("0000000000000000");
            plain = GetBytes("0000000000000000");
            correctResult = GetBytes("4EF997456198DD78");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");


            /****************************/
            key = GetBytes("FFFFFFFFFFFFFFFF");
            plain = GetBytes("FFFFFFFFFFFFFFFF");
            correctResult = GetBytes("51866FD5B85ECB8A");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");

            /****************************/
            key = GetBytes("3000000000000000");
            plain = GetBytes("1000000000000001");
            correctResult = GetBytes("7D856F9A613063F2");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");

            /****************************/
            key = GetBytes("1111111111111111");
            plain = GetBytes("1111111111111111");
            correctResult = GetBytes("2466DD878B963C9D");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");


            /****************************/

            key = GetBytes("0113B970FD34F2CE");
            plain = GetBytes("059B5E0851CF143A");
            correctResult = GetBytes("48F4D0884C379918");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");


            /****************************/

            key = GetBytes("1C587F1C13924FEF");
            plain = GetBytes("305532286D6F295A");
            correctResult = GetBytes("55CB3774D13EF201");

            blowfish = new BlowfishTransform(algo, true, key, null);
            blowfish.TransformBlock(plain, 0, plain.Length, cipher, 0);

            blowfish = new BlowfishTransform(algo, false, key, null);
            blowfish.TransformBlock(cipher, 0, cipher.Length, decipher, 0);

            Assert.AreEqual(cipher, correctResult, "Error in encryption");
            Assert.AreEqual(plain, decipher, "Error in decryption");





        }

        #endregion

#region StringCryptTest
        [Test]
        public void StringCryptTest()
        {
            StringCrypt encrypt = new StringCrypt("secret password");
            StringCrypt decrypt = new StringCrypt("secret password");

            Assert.IsTrue(encrypt.VerifyKey("secret password", encrypt.KeyChecksum), "Error in KeyChecksum");
            Assert.IsFalse(encrypt.VerifyKey("wrong password", encrypt.KeyChecksum), "Error in KeyChecksum");

            for(int i=0;i<10;i++)
            {
                string plain = "data".PadRight(i*100, 'P');
                string cipher =  decrypt.Decrypt(encrypt.Encrypt(plain));
                Assert.AreEqual(cipher, plain);
            }
        }
        #endregion

#region StreamCipherTest
        [Test]
        public void StreamCipherTest()
        {
            CFBTest();
            CTRTest();
            OFBTest();
        }

        public void CFBTest()
        {
            Twofish algo = new Twofish();
            algo.Key = new byte[16];
            algo.IV = new byte[16];

         
            

            StreamCipher cipher = new StreamCipher(algo);
            cipher.StreamMode = StreamMode.CFB;

            byte[] input = new byte[4];
            byte[] output = new byte[input.Length * 32];

            for (int i = 0; i < 32; i++)
            {
                cipher.Encrypt(input, 0, input.Length, output, i * input.Length);
            }



            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;
            ICryptoTransform transform = algo.CreateEncryptor();


            byte[] correctResult = new byte[128];
            byte[] lastResult = algo.IV;

            for (int i = 0; i < 8; i++)
            {
                transform.TransformBlock(lastResult, 0, 16, correctResult, i * 16);
                Buffer.BlockCopy(correctResult, i * 16, lastResult, 0, 16);
            }


            Assert.AreEqual(correctResult, output);


            //Decryption
            byte[] decipher = new byte[output.Length];
            CryptRand.Instance.GetBytes(decipher); //Fill decipher with random bytes

            cipher.Decrypt(output, decipher);

            Assert.AreEqual(new byte[decipher.Length], decipher);




            algo = new Twofish();
            algo.Key = new byte[16];
            algo.IV = new byte[16];

            cipher = new StreamCipher(algo);

            MemoryStream mStream = new MemoryStream();
            CryptoStream cStream = new CryptoStream(mStream, cipher.CreateEncryptor(), CryptoStreamMode.Write);
            byte[] buffer = new byte[8];

            cStream.Write(buffer, 0, buffer.Length);
            cStream.Flush();

            cStream.Write(buffer, 0, buffer.Length);
            cStream.Flush();

            cStream.Write(buffer, 0, buffer.Length);
            cStream.Flush();

            cStream.Close();

            byte[] res = mStream.ToArray();

            mStream = new MemoryStream();
            cStream = new CryptoStream(mStream, cipher.CreateDecryptor(algo.Key, algo.IV), CryptoStreamMode.Write);
            cStream.Write(res, 0, res.Length);
            cStream.Flush();
            cStream.Close();

            decipher = mStream.ToArray();

            Assert.AreEqual(decipher, new byte[24]);




            StreamCipher test = new StreamCipher();
            buffer = Encoding.UTF8.GetBytes("Hello World");
            byte[] secret = new byte[buffer.Length * 8];

            for (int i = 0; i < 8; i++)
                test.Encrypt(buffer, 0, buffer.Length, secret, i * buffer.Length);

            StreamCipher decrypt = new StreamCipher(test.Key, test.IV);

            decipher = new byte[secret.Length];
            decrypt.Decrypt(secret, decipher);
            
         

            correctResult = new byte[secret.Length];
            for (int i = 0; i < 8; i++)
                Buffer.BlockCopy(buffer, 0, correctResult, buffer.Length * i, buffer.Length);


            Assert.AreEqual(correctResult, decipher);
            //string s = Encoding.UTF8.GetString(decipher);
            
        }

        public void CTRTest()
        {
            Twofish algo = new Twofish();
            algo.Key = new byte[16];
            algo.IV = new byte[16];
          

          
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;
            ICryptoTransform transform = algo.CreateEncryptor();

            StreamCipher cipher = new StreamCipher(algo);
            cipher.StreamMode = StreamMode.CTR;

            byte[] input = new byte[4];
            byte[] output = new byte[input.Length * 32];

            for (int i = 0; i < 32; i++)
            {
                cipher.Encrypt(input, 0, input.Length, output, i * input.Length);
            }           
            


            byte[] correctResult = new byte[128];
            byte[] lastResult = algo.IV;

            for (int i = 0; i < 8; i++)
            {
                transform.TransformBlock(lastResult, 0, 16, correctResult, i * 16);

                //Increment lastResult by 1
                int j = lastResult.Length - 1;
                do
                {
                    lastResult[j--]++;
                } while (j >= 0 && lastResult[j + 1] == 0);               
            }

            Assert.AreEqual(correctResult, output);


            StreamCipher test = new StreamCipher();
            test.StreamMode = StreamMode.CTR;
            byte[] buffer = buffer = Encoding.UTF8.GetBytes("Hello World");
            byte[] secret = new byte[buffer.Length * 8];

            for (int i = 0; i < 8; i++)
                test.Encrypt(buffer, 0, buffer.Length, secret, i * buffer.Length);

            StreamCipher decrypt = new StreamCipher(test.Key, test.IV);
            decrypt.StreamMode = StreamMode.CTR;

            byte[] decipher = new byte[secret.Length];
            decrypt.Decrypt(secret, decipher);

            correctResult = new byte[secret.Length];
            for (int i = 0; i < 8; i++)
                Buffer.BlockCopy(buffer, 0, correctResult, buffer.Length * i, buffer.Length);


            Assert.AreEqual(correctResult, decipher);

            //string s = Encoding.UTF8.GetString(decipher);
        }

        public void OFBTest()
        {
            Twofish algo = new Twofish();
            algo.Key = new byte[16];
            algo.IV = new byte[16];
          

          
            algo.Mode = CipherMode.ECB;
            algo.Padding = PaddingMode.None;
            ICryptoTransform transform = algo.CreateEncryptor();

            StreamCipher cipher = new StreamCipher(algo);
            cipher.StreamMode = StreamMode.OFB;

            byte[] input = new byte[4];
            byte[] output = new byte[input.Length * 32];

            for (int i = 0; i < 32; i++)
            {
                cipher.Encrypt(input, 0, input.Length, output, i * input.Length);
            }           
            


            byte[] correctResult = new byte[128];
            byte[] lastResult = algo.IV;

            for (int i = 0; i < 8; i++)
            {
                transform.TransformBlock(lastResult, 0, 16, correctResult, i * 16);
                Buffer.BlockCopy(correctResult, i * 16, lastResult, 0, 16);
            }

            Assert.AreEqual(correctResult, output);


            StreamCipher test = new StreamCipher();
            test.StreamMode = StreamMode.OFB;
            byte[] buffer = buffer = Encoding.UTF8.GetBytes("Hello World");
            byte[] secret = new byte[buffer.Length * 8];

            for (int i = 0; i < 8; i++)
                test.Encrypt(buffer, 0, buffer.Length, secret, i * buffer.Length);

            StreamCipher decrypt = new StreamCipher(test.Key, test.IV);
            decrypt.StreamMode = StreamMode.OFB;

            byte[] decipher = new byte[secret.Length];
            decrypt.Decrypt(secret, decipher);

            correctResult = new byte[secret.Length];
            for (int i = 0; i < 8; i++)
                Buffer.BlockCopy(buffer, 0, correctResult, buffer.Length * i, buffer.Length);


            Assert.AreEqual(correctResult, decipher);

            //string s = Encoding.UTF8.GetString(decipher);
        }
        #endregion

        #endregion

#region Subfunctions
        /// <summary>
        /// Returns the bytes a hexadezimal string represents
        /// </summary>       
        private byte[] GetBytes(string s)
        {
            byte[] result = new byte[s.Length >> 1];

            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);

            return result;
        }
        #endregion
    }

}
#endif