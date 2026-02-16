Test vectors with some E2E test cases for BLS12-381 bindings
We provide test-vectors for the following use cases:

1. BLS signature with the public key over G1. This function returns a message `msg`, a public
key `pk`, and a signature `sig`. Verification of these test vectors should proceed as follows:
   * pk_deser = G1Decompress(pk)
   * sig_deser = G2Decompress(sig)
   * hashed_msg = G2HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
   * Check that pairing(pk_deser, hashed_msg) = pairing(G1Generator, sig_deser)
2. BLS signature with the public key over G2. This function returns a message `msg`, a public
key `pk`, and a signature `sig`. Verification of these test vectors should proceed as follows:
   * pk_deser = G2Decompress(pk)
   * sig_deser = G1Decompress(sig)
   * hashed_msg = G1HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
   * Check that pairing(hashed_msg, pk_deser) = pairing(sig_deser, G2Generator)
3. Aggregate BLS signature with the same key and different messages, with public key over G1. This
function returns a list of 10 messages {`msg_1`, ..., `msg_10`}, a public key `pk`, and an
aggregate signature `aggr_sig`. To verify the correctness of the test vectors, check the
following:
   * hashed_msg_i = G2HashToCurve(msg_i, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") for i in [1, 10]
   * pk_deser = G1Decompress(pk)
   * aggr_sig_deser = G2Decompress(aggr_sig)
   * aggr_msg = sum_{i\in[1,10]} hashed_msg_i
   * Check that pairing(pk_deser, aggr_msg) = pairing(G1Generator, aggr_sig_deser)
4. Aggregate BLS signature with different keys and same message, with public key over G2. This
function returns a message `msg`, ten public keys `{pk_1,...,pk_10}`, and an
aggregate signature `aggr_sig`. To verify the correctness of the test vectors, check the
following:
   * hashed_msg = G1HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
   * pk_deser_i = G2Decompress(pk_i) for i in [1, 10]
   * ds_scalar = SHA256(pk_1 || .. || pk_10)[..16] (where [..16] represent the first 16 bytes)
   * aggr_sig_deser = G1Decompress(aggr_sig)
   * aggr_pk = sum_{i\in[1,10]} ds_scalar^i * pk_deser_i
   * Check that pairing(hashed_msg, aggr_pk) = pairing(aggr_sig_deser, G2Generator)
5. FastAggregate BLS signature with different keys and same message, with PK over G1.
Assumes `PoP(pk_i)` has already been verified for all i (per IETF `FastAggregateVerify`).
This function returns a message `msg`, ten public keys `{pk_1, ..., pk_10}` (G1 compressed)
and an aggregated signature `aggr_sig` (G2 compressed). To verify the correctness of the test vector,
check the following:
   * hashed_msg = G2HashToCurve(msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
   * aggr_pk = sum_i G1Decompress(pk_i)
   * aggr_sig_deser = G2Decompress(aggr_sig)
   * Check that pairing(aggr_pk, hashed_msg) == pairing(G1Generator, aggr_sig_deser)
6. FastAggregate BLS signature with different keys and same message, with PK over G2.
Assumes `PoP(pk_i)` has already been verified for all i (per IETF `FastAggregateVerify`).
This function returns a message `msg`, ten public keys `{pk_1, ..., pk_10}` (G2 compressed)
and an aggregated signature `aggr_sig` (G1 compressed). To verify the correctness of the test vector,
check the following:
   * hashed_msg = G1HashToCurve(msg, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
   * aggr_pk = sum_i G2Decompress(pk_i)
   * aggr_sig_deser = G1Decompress(aggr_sig)
   * Check that pairing(hashed_msg, aggr_pk) == pairing(aggr_sig_deser, G2Generator)
7. Schnorr signature in G1. This function returns a message `msg`, a public key `pk` and a
signature `(A, r)`. To verify the signature, proceed as follows:
  * c = Sha256(A || pk || msg)[..16]
  * pk_deser = G1Decompress(pk)
  * A_deser = G1Decompress(A)
  * r_deser = IntegerFromBytes(r)
  * Check that r_deser * G1Generator = A_deser + c * pk_deser
8. Schnorr signature in G2. This function returns a message `msg`, a public key `pk` and a
signature `(A, r)`.To verify the signature, proceed as follows:
   * hash = Sha256(A || pk || msg)[..16]
   * pk_deser = G2Decompress(pk)
   * A_deser = G2Decompress(A)
   * r_deser = IntegerFromBytes(r)
   * Check that r_deser * G2Generator = A_deser + c * pk_deser

```
+---------------------------------------------------------------------------+
|            Test vectors for E2E with BLS12-381 bindings                   |
+---------------------------------------------------------------------------+
|                                                                           |
+---------------------------------------------------------------------------+
|                 BLS signature with PK in G1                               |
+---------------------------------------------------------------------------+
| Message   : 0x3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e
| Public key: 0xaa04a34d4db073e41505ebb84eee16c0094fde9fa22ec974adb36e5b3df5b2608639f091bff99b5f090b3608c3990173
| Signature : 0x808ccec5435a63ae01e10d81be2707ab55cd0dfc235dfdf9f70ad32799e42510d67c9f61d98a6578a96a76cf6f4c105d09262ec1d86b06515360b290e7d52d347e48438de2ea2233f3c72a0c2221ed2da5e115367bca7a2712165032340e0b29
| PoP       : 0xa873bfe32ed52ffb33a490aafb69955fee8dc4ea243be0d6fbb77dad5537a7146f559fb93422583153b6d37d6beec9c0103b8a6d4de51678191c20c1ab6b280bdb7594fc644fe70c315d3dbf35e31ef4bf9f6de97fe6e7828be4d5c14dfacb91
|
+---------------------------------------------------------------------------+
|                    BLS signature with PK in G2                            |
+---------------------------------------------------------------------------+
| Message   : 0x5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa
| Public key: 0xb4953c4ba10c4d4196f90169e76faf154c260ed73fc77bb65dc3be31e0cec614a7287cda94195343676c2c57494f0e651527e6504c98408e599a4eb96f7c5a8cfb85d2fdc772f28504580084ef559b9b623bc84ce30562ed320f6b7f65245ad4
| Signature : 0x8e02b7950198d335c7b352d18880e2f6b4e7f6780298872b67840db1faa069f9a8be48800ce2ee5565a811d8230d3f05
| PoP       : 0x9775f532816da49dd464f1239f7d70a16ca9d26e7abbd7a781e5332f6723749cbedb88cea0d8451ceb9c2fbd3fc42fcd
|
+---------------------------------------------------------------------------+
| Aggregate BLS signature with same key, different message, with PK over G1 |
+---------------------------------------------------------------------------+
| Messages   :
|    1. 0x2ba037cdb63cb5a7277dc5d6dc549e4e28a15c70670f0e97787c170485829264
|    2. 0xecbf14bddeb68410f423e8849e0ce35c10d20a802bbc3d9a6ca01c386279bf01
|    3. 0xe8f75f478cb0d159db767341602fa02d3e01c3d9aacf9b686eccf1bb5ff4c8fd
|    4. 0x21473e89d50f51f9a1ced2390c72ee7e37f15728e61d1fb2c8c839495e489052
|    5. 0x8c146d00fe2e1caec31b159fc42dcd7e06865c6fa5267c6ca9c5284e651e175a
|    6. 0x362f469b6e722347de959f76533315542ffa440d37cde8862da3b3331e53b60d
|    7. 0x73baeb620e63a2e646ea148974350aa337491e5f5fc087cb429173d1eeb74f5a
|    8. 0x73acc6c3d72b59b8bf5ab58cdcf76aa001689aac938a75b1bb25d77b5382898c
|    9. 0x4e73ba04bae3a083c8a2109f15b8c4680ae4ba1c70df5b513425349a77e95d3b
|    10. 0x565825a0227d45068e61eb90aa1a4dc414c0976911a52d46b39f40c5849e5abe
| Public key: 0x97c919babda8d928d771d107a69adfd85a75cee2cedc4afa4c0a7e902f38b340ea21a701a46df825210dd6942632b46c
| Aggregate Signature : 0xb425291f423235b022cdd038e1a3cbdcc73b5a4470251634abb874c7585a3a05b8ea54ceb93286edb0e9184bf9a852a1138c6dd860e4b756c63dff65c433a6c5aa06834f00ac5a1a1acf6bedc44bd4354f9d36d4f20f66318f39116428fabb88
|
+---------------------------------------------------------------------------+
| Aggregate BLS signature with different key, same message, with PK over G2 |
+---------------------------------------------------------------------------+
| Message    : 0xe345b7f2c017b16bb335c696bc0cc302f3db897fa25365a2ead1f149d87a97e8
| Public keys:
|    1. 0x83718f20d08471565b3a6ca6ea82c1928e8730f87e2afe460b74842f2880facd8e63b8abcdcd7350fe5813a08aa0efed13216b10de1c56dc059c3a8910bd97ae133046ae031d2a53a44e460ab71ebda94bab64ed7478cf1a91b6d3981e32fc95
|    2. 0x814f825911bd066855333b74a3cc564d512503ee29ea1ec3bd57a3c07fa5768ad27ea1ddd8047f43fbc9a4ebda897c1406415fefbb8838b8782aa747e2fde7b1813d0f89fad06c8971041c9427abf848503e34e3ca033ba85d50b72ffac4be4a
|    3. 0x9974c70513ed5538a8e55f5ce1a0267282b9e8431e25ae566950b2d0793a44a0a3c52110f4d83d694a5296615ee68573098c14d255783a9b1a169d2be1baefbef914a4f830a9099f720063914cc919064d2244582bb9f302eac39c8b195cf3d2
|    4. 0x894a3a01d38169a38bea13097cf904dd3ff9dceefb51e8b539725a237ae55a361758be1cdf0e21a7b8db3599adaf2305050f1d8450b924a4b910ff536fc2f7960cd3251c2a457b975d46f7c0f74493cc9b5e8d2fed2e489363e641cc79933d1e
|    5. 0x9646da0149ed140e33a99e1ffc5fe9c97c2368ca273544024993cdcb7aa04c0be936e6d4427747e62c4caea4fe1f69e5162fad222e0487f5556524c9d3db74921e1c0f5893f0e26c759e3873e8fd6637e6051f70ef9a3363cf284e8eee67bcf3
|    6. 0xb75743fb2f8321ac56cee19aacd7e141a3592b7230992ea84d8800d45ad71924a477f61cf9d4a2783df59dac21cd17e70e4ce5d526cbe73edc4a10b78fa56a2ef34d2009f2756d2d50188031e026a6a1dadcd5e753f5e7f7276048277d3819f1
|    7. 0x873c1e7d525265afa8c037d33874261a90daaa2c6ed5e46ed043ec48a28b7111d0de65800aa72448c1fdb1026ba076bd04193bd2d04e0de63e7a008b8417420eb4920767a1d32f6330ed25bdb4dc7726d989d6cf192db6b32728bb388195ba27
|    8. 0xb993f867f9f1f84c3c5c3e5b80013055da7705491c36a80e1201a6a503d7364000c50bc27e03477646874a3074cc4e390febfea78a2b4d0e40c57d6deaf9fae430a19fcce0c03f43ff8f7e788de0c7b8ce1b69b69d1d026175c8f2730777866d
|    9. 0x99836a204576636f34a4663cfa7e02a05cb2d4fd1b582427d199ac3ddac6f087968d2290198aa15e04f6e7e0d070b7dd03607db9c2e4b17709853c30b2f6490261599408fbbc17371de74d0a2a76ff10cd8c9b55461c444bbebc82547bb40c9f
|    10. 0x96f8d678f40dd83b2060e14372d0bc43a423fecac44f082afd89cb481b855885ac83fb366516dc74023cc41a0c606be2067ba826ea612f84c9f0e895d02bc04d6c34e201ff8c26cc22cb4c426c53f503d8948eafceb12e2f4b6ad49b4e051690
| Aggregate Signature : 0xab94c30fb1f46f521c36563decea526fc48428fe2e3b76f6d3a6c01ff4d0e7e8410a8d51895d13a05439673c17c245c6
|
+---------------------------------------------------------------------------+
| FastAggregate BLS sig (same msg, different keys), PK over G1 (PoP assumed) |
+---------------------------------------------------------------------------+
| Message    : 0x0558db9aff738e5421439601e7f30e88b74f43b80c1d172b5d371ce0dc05c912
| Public keys:
|    1. 0xb91cacee903a53383c504e9e9a39e57d1eaa6403d5d38fc9496e5007d54ca92d106d1059f09461972aa98514d07000ae
|    2. 0x8477e8491acc1cfbcf675acf7cf6b92e027cad7dd604a0e8205703aa2cc590066c1746f89e10d492d0230e6620c29726
|    3. 0x887e8fd9c5f80beb5d0c50a2c536dffd5563dcd7fcc09dcf1aace5f481429344514b380affbc28f116a8e137fec52e90
|    4. 0xb4928475f56d224ef82ee50ee5abc393e5894d0222068c4ade1d5a5118861b3c1486b747a759142ef75c61c74abcb82c
|    5. 0xb15f02441de609ab5ee7b61c3350116461a48b7d530f8b1f3abf57d1fc29659d3fe05d6b7dae6ad26ba36921a91c935a
|    6. 0xa1199c1a689c1b27ac1e902afdf3eb42f0a5231c9db61420fdeb58cd531ff98ebb7035c2fb6803aaaaad90c74e3ab6f3
|    7. 0xb632708c4fe78944ae481ddfcbe51eb38b18292966bdce5870ed2d16a556e6a60e2f72f16643244f533c26dd97e309f4
|    8. 0x96804e572530fd75667fc38da98ef71eda385000c5a5e1ce96ec54cfa94f494fb63c9a2bf94fda410934a5d1cb04218f
|    9. 0xa0c2f005e87379a00a38d92fcc4927087b84a3a5284feac624db3ad6bdcc4174f25d3422b4427e2674c7546f180825ea
|    10. 0xa14d1004c8166915fc125f03b2c5c80976c440d0c819e87912bd4f32d5dd914c3767b355bd8baef2a671d421a792e4a8
| Aggregate Signature : 0xb359beeff652ba34474f98019f389e39bac0ff8f3b49bdb9a6e0a67da895c50431746da1faf0e8ec53d15aa90e02aef7045147840791d7d205d077acc797a40b14880769f3568babf49f45a59b2d7de199369386c7a7267fcdddc2bc36b67318
|
+---------------------------------------------------------------------------+
| FastAggregate BLS sig (same msg, different keys), PK over G2 (PoP assumed) |
+---------------------------------------------------------------------------+
| Message    : 0x0558db9aff738e5421439601e7f30e88b74f43b80c1d172b5d371ce0dc05c912
| Public keys:
|    1. 0x99325b8e11a6a1d137a4ccc09574dcfa54162f3eca88656e4aa8a8ee0e32842ff9bdbcf90800ff4b6196421a930def3d00e948c1fc67b71597ad78819fd1163daa68b419556be8dc64e48086b7604583d8beaffe755710b4b80effa910c6050d
|    2. 0xb82da86bd84f82cc6b3f1df65ebe754d2199e49f6791a0d6db136304ab4610fadcbdf7bac09e6e10b6850aafa0b258bb08bee0214ce3fbfaa97371e67d57fc27bb423ba07d092bf6f584c5f2be72a8b2c02045de23af01bb04e9bf5be0a1d15c
|    3. 0x99a7fff545393ac442bdf0c6043de7461301ad7ea3402f4ddf89e19c671faf28989c28251ad63385ec9dbb81857b9d3301ff6ebe7e16f21a86bf48c40f64fd27fad2c2a6b93305ae6448ba8b3756ea4d6fbbac859231e65b0242916a34b0a67a
|    4. 0xa6444b7a2ef32fc83d85973945569d30a6dff7feb5840254a9a81fc0f78a70a97905cf196faa5f47ab6f26a0750b8f610b000537c8f73a511db4bd1657c47b531b95be021817bde5345d1c6daf10064a219def36465b0bf5c295df2ebde63535
|    5. 0xab92c359bdccc19e44fd47120cc6d0a1d3955af9e6be18c1b084e397442055c597ff92ec134c9d8f2a788a96b28f3af4108239e00339840f3bfb666eea21e87c02bd69edca6502f7805a6dfd29fb4db4052a321abbb857621992fc383f368c91
|    6. 0x872e0b3f67274e0808e326601ef42e22edf880f12d4d044ba5d75bf078aa0ebcad085376c15d1cc09eb8c8c9797572da003826536c8a06bdea226e6b2e0cc111ad1e645fd6c38190a72f42f514397d470534c161d028690dafb95cb1f19ff9c0
|    7. 0xacfc575fee9be2dd324940c3cb873213532a9eddc2f546a2d8c56b5b015e2521173a4d2c05acca14aa97c6224a223b46140b3483f06ea7a2a2db3961a74074e58653549220713aa6edc8a21bbb04f468d684f7656882543143ed4cf3d5bcae69
|    8. 0xac0c74306cf12d21d4889d7b28e562278a6849b0b2e152968cc23dbe7b6cf7a75a62858068d9f1dde5bf90a35e89a81e0a008a28dbcd81697fb87f603895b6361c8dfdf21110633e93f33120d8e0f7ba7c0693173e55d5b3e1284a18be5ec773
|    9. 0x8b7cd629f5a07ddca6be75585cfc12622789811edf9d4c86ce433927450ed484942b7b377eaa383746d54bcedf1d616d0cb0fa2101e5358884578860a5960653664dbd77bb3afa61af7434c10a74636c2cbe1d61db5b47102ee017c1ab81fe7f
|    10. 0xa27b12206e80a5e0d52d9b817bfb0097c87534b4332f430f1ad1978d8a9e33cfe63123029f64408fea181e22d25dc7c80756cb011387ad545026cc7af9a7047043b44bf07682c03a0fc7f61017ba21d842535b449afe1e7d5d51a7660f71f6b3
| Aggregate Signature : 0xb0887f5c2e85596a8233cc26ce0ae94cdf0e1da3465075016a633d77de8acaefbc86497b484cf0beb36a3af90b38c3ce
|
+---------------------------------------------------------------------------+
|                      Schnorr signature over G1                            |
+---------------------------------------------------------------------------+
| Message   : 0x0558db9aff738e5421439601e7f30e88b74f43b80c1d172b5d371ce0dc05c912
| Public key: 0xb91cacee903a53383c504e9e9a39e57d1eaa6403d5d38fc9496e5007d54ca92d106d1059f09461972aa98514d07000ae
| Signature : (0x8477e8491acc1cfbcf675acf7cf6b92e027cad7dd604a0e8205703aa2cc590066c1746f89e10d492d0230e6620c29726, 0x4e908280c0100cfe53501171ffa93528b9e2bb551d1025decb4a5b416a0aee53)
|
+---------------------------------------------------------------------------+
|                      Schnorr signature over G2                            |
+---------------------------------------------------------------------------+
| Message   : 0x2b71175d0486006a33f14bc4e1fe711a3d4a3a3549b230013240e8f80e54372f
| Public key: 0x88370a4b4ddc627613b0396498fb068f1c1ff8f2aa6b946a9fc65f930d24394ddc45042e602094f6a88d49a8a037e78108dce014586ff5ff5744842f382e3917d180c7eb969585748d20ae8c6e07ca786e8da7ea2c7bdef5ae1becebe4da59ad
| Signature : (0x964851eb8823492c8720bf8c515b87043f5bab648000e63cfb6fc6fcdf6709061e0035c315cd23d239866471dea907d91568b69297dc8c4360f65d0bd399c2de19781c13bbf3a82ff1fcab8ac9f688ed96d6f2ea9a8ed057e76f0347d858ae22, 0x2c5a22cb1e2fb77586c0c6908060b38107675a6277b8a61b1d6394a162af6718)
```