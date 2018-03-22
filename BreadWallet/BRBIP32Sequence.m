//
//  BRBIP32Sequence.m
//  TosWallet
//
//  Created by Aaron Voisine on 7/19/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//  Copyright © 2016 Litecoin Association <loshan1212@gmail.com>
//  Copyright (c) 2018 Blockware Corp. <admin@blockware.co.kr>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRBIP32Sequence.h"
#import "BRKey.h"
#import "NSString+Bitcoin.h"
#import "NSData+Bitcoin.h"
#import "NSMutableData+Bitcoin.h"
#import <Foundation/Foundation.h> //t

#define BIP32_SEED_KEY "Bitcoin seed"
//#define BIP32_XPRV     "76066276" //t // "\x04\x88\xAD\xE4"  0488ADE4
//#define BIP32_XPUB     "76067358" //t // "\x04\x88\xB2\x1E"  0488B21E
#define BIP32_XPRV     "\x04\x88\xAD\xE4"
#define BIP32_XPUB     "\x04\x88\xB2\x1E"


// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

// Private parent key -> private child key
//
// CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
//       (Note: The 0x00 pads the private key to make it 33 bytes long.)
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key ki is parse256(IL) + kpar (mod n).
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i
//   (Note: this has probability lower than 1 in 2^127.)
//
static void CKDpriv(UInt256 *k, UInt256 *c, uint32_t i)
{
//    NSLog(@"Call_ Function(CKDpriv)"); //a
    uint8_t buf[sizeof(BRECPoint) + sizeof(i)];
    UInt512 I;
    
    if (i & BIP32_HARD) {
        buf[0] = 0;
        *(UInt256 *)&buf[1] = *k;
    }
    else BRSecp256k1PointGen((BRECPoint *)buf, k);

    *(uint32_t *)&buf[sizeof(BRECPoint)] = CFSwapInt32HostToBig(i);

    HMAC(&I, SHA512, sizeof(UInt512), c, sizeof(*c), buf, sizeof(buf)); // I = HMAC-SHA512(c, k|P(k) || i)
    
    BRSecp256k1ModAdd(k, (UInt256 *)&I); // k = IL + k (mod n)
    *c = *(UInt256 *)&I.u8[sizeof(UInt256)]; // c = IR
    
    memset(buf, 0, sizeof(buf));
    memset(&I, 0, sizeof(I));
}

// Public parent key -> public child key
//
// CKDpub((Kpar, cpar), i) -> (Ki, ci) computes a child extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): return failure
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key Ki is point(parse256(IL)) + Kpar.
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with
//   the next value for i.
//
static void CKDpub(BRECPoint *K, UInt256 *c, uint32_t i)
{
//    NSLog(@"Call_BRBIP32Sequence.m Function(CKDpub)"); //a
    if (i & BIP32_HARD ) return; // can't derive private child key from public parent key

    uint8_t buf[sizeof(*K) + sizeof(i)];
    UInt512 I;
    
    *(BRECPoint *)buf = *K;
    *(uint32_t *)&buf[sizeof(*K)] = CFSwapInt32HostToBig(i);

    HMAC(&I, SHA512, sizeof(UInt512), c, sizeof(*c), buf, sizeof(buf)); // I = HMAC-SHA512(c, P(K) || i)
    
    *c = *(UInt256 *)&I.u8[sizeof(UInt256)]; // c = IR
    BRSecp256k1PointAdd(K, (UInt256 *)&I); // K = P(IL) + K
    
    memset(buf, 0, sizeof(buf));
    memset(&I, 0, sizeof(I));
}

// helper function for serializing BIP32 master public/private keys to standard export format
static NSString *serialize(uint8_t depth, uint32_t fingerprint, uint32_t child, UInt256 chain, NSData *key)
{
//    NSLog(@"Call_BRBIP32Sequence.m Function(serialize)"); //a
    NSMutableData *d = [NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)];

    fingerprint = CFSwapInt32HostToBig(fingerprint);

    NSLog(@"TEST_fingerprint : %u", fingerprint); //t
    child = CFSwapInt32HostToBig(child);

    [d appendBytes:key.length < 33 ? BIP32_XPRV : BIP32_XPUB length:4];
    [d appendBytes:&depth length:1];
    [d appendBytes:&fingerprint length:sizeof(fingerprint)];
    [d appendBytes:&child length:sizeof(child)];
    [d appendBytes:&chain length:sizeof(chain)];
    if (key.length < 33) [d appendBytes:"\0" length:1];
    [d appendData:key];
    
//    NSLog(@"TEST_BRBIP32Sequence.m(serialize)_base58checkWithData : %@", [NSString base58checkWithData:d]); //t
    return [NSString base58checkWithData:d];
}

@implementation BRBIP32Sequence

// MARK: - BRKeySequence

// master public key format is: 4 byte parent fingerprint || 32 byte chain code || 33 byte compressed public key
// the values are taken from BIP32 account m/0H
- (NSData *)masterPublicKeyFromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(masterPublicKeyFromSeed)_seed : %@", seed); //a
    if (! seed) return nil;

    NSMutableData *mpk = [NSMutableData secureData];
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);

    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    
    [mpk appendBytes:[BRKey keyWithSecret:secret compressed:YES].hash160.u32 length:4];
    
    CKDpriv(&secret, &chain, 0 | BIP32_HARD); // account 0H
    
    [mpk appendBytes:&chain length:sizeof(chain)];
    [mpk appendData:[BRKey keyWithSecret:secret compressed:YES].publicKey];

//    NSLog(@"TEST_BRBIP32Sequence.m(masterPublicKeyFromSeed)_mpk : %@", mpk); //t (masterPubKey == mpk)
    return mpk;
}

- (NSData *)publicKey:(uint32_t)n internal:(BOOL)internal masterPublicKey:(NSData *)masterPublicKey
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(publicKey)"); //a
    if (masterPublicKey.length < 4 + sizeof(UInt256) + sizeof(BRECPoint)) return nil;

    UInt256 chain = *(const UInt256 *)((const uint8_t *)masterPublicKey.bytes + 4);
    BRECPoint pubKey = *(const BRECPoint *)((const uint8_t *)masterPublicKey.bytes + 36);

    CKDpub(&pubKey, &chain, internal ? 1 : 0); // internal or external chain
    CKDpub(&pubKey, &chain, n); // nth key in chain PP

//    NSLog(@"TEST_[NSData dataWithBytes:&pubKey length:sizeof(pubKey)] : %@", [NSData dataWithBytes:&pubKey length:sizeof(pubKey)]);
    return [NSData dataWithBytes:&pubKey length:sizeof(pubKey)];
}

- (NSString *)privateKey:(uint32_t)n internal:(BOOL)internal fromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(privateKey)"); //a
    return seed ? [self privateKeys:@[@(n)] internal:internal fromSeed:seed].lastObject : nil;
}

- (NSArray *)privateKeys:(NSArray *)n internal:(BOOL)internal fromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(privateKeys)"); //a
    if (! seed || ! n) return nil;
    if (n.count == 0) return @[];

    NSMutableArray *a = [NSMutableArray arrayWithCapacity:n.count];
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    uint8_t version = BITCOIN_PRIVKEY;
    
#if BITCOIN_TESTNET
    version = BITCOIN_PRIVKEY_TEST;
#endif

    CKDpriv(&secret, &chain, 0 | BIP32_HARD); // account 0H
    CKDpriv(&secret, &chain, internal ? 1 : 0); // internal or external chain

    for (NSNumber *i in n) {
        NSMutableData *privKey = [NSMutableData secureDataWithCapacity:34];
        UInt256 s = secret, c = chain;
        
        CKDpriv(&s, &c, i.unsignedIntValue); // nth key in chain

        [privKey appendBytes:&version length:1];
        [privKey appendBytes:&s length:sizeof(s)];
        [privKey appendBytes:"\x01" length:1]; // specifies compressed pubkey format
        [a addObject:[NSString base58checkWithData:privKey]];
    }

    return a;
}

// MARK: - authentication key

- (NSString *)authPrivateKeyFromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(authPrivateKeyFromSeed)"); //a
    if (! seed) return nil;
    
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
//    NSLog(@"TEST_BRBIP32Sequence.m(authPrivateKeyFromSeed)_[BIP32_SEED_KEY] : %s", BIP32_SEED_KEY); //t
//    NSLog(@"TEST_BRBIP32Sequence.m(authPrivateKeyFromSeed)_[strlen+BIP32_SEED_KEY] : %lu", strlen(BIP32_SEED_KEY)); //t
    
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    uint8_t version = BITCOIN_PRIVKEY;

#if BITCOIN_TESTNET
    version = BITCOIN_PRIVKEY_TEST;
#endif
    //t
    // path m/1H/0 (same as copay uses for bitauth)
    /*
    CKDpriv(&secret, &chain, 1 | BIP32_HARD);
    CKDpriv(&secret, &chain, 0);
    */
//    CKDpriv(&secret, &chain, 44 | BIP32_HARD);
//    CKDpriv(&secret, &chain, 99 | BIP32_HARD);
//    CKDpriv(&secret, &chain, 0 | BIP32_HARD);

    CKDpriv(&secret, &chain, 1 | BIP32_HARD);
    CKDpriv(&secret, &chain, 0);
    
    NSMutableData *privKey = [NSMutableData secureDataWithCapacity:34];
    
    [privKey appendBytes:&version length:1];
    [privKey appendBytes:&secret length:sizeof(secret)];
    [privKey appendBytes:"\x01" length:1]; // specifies compressed pubkey format

//    NSLog(@"TEST_BRBIP32Sequence.m(authPrivateKeyFromSeed)_[NSString base58checkWithData:privKey1] : %@", privKey); //t // <b0e4cb65 66095a70 e5d310ab 2f170a75 dd3bdf80 bb8c34b9 e759cab5 4f447c82 e801>
    
//    NSLog(@"TEST_BRBIP32Sequence.m(authPrivateKeyFromSeed)_[NSString base58checkWithData:privKey2] : %@", [NSString base58checkWithData:privKey]); //t // TAiiw78fn7fAMiz7pi28LN8WrRdA1AcvnKyPsQSSuWCK924yivpa

    /*
    NSLog(@"TEST_base58 : %@", [NSString base58checkWithData:@"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]);
    */
    return [NSString base58checkWithData:privKey];
}

// key used for BitID: https://github.com/bitid/bitid/blob/master/BIP_draft.md
- (NSString *)bitIdPrivateKey:(uint32_t)n forURI:(NSString *)uri fromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(bitIdPrivateKey)"); //a
    NSUInteger len = [uri lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *data = [NSMutableData dataWithCapacity:sizeof(n) + len];
    
    [data appendUInt32:n];
    [data appendBytes:uri.UTF8String length:len];

    UInt256 hash = data.SHA256;
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    uint8_t version = BITCOIN_PRIVKEY;
    
#if BITCOIN_TESTNET
    version = BITCOIN_PRIVKEY_TEST;
#endif

    CKDpriv(&secret, &chain, 13 | BIP32_HARD); // m/13H
    CKDpriv(&secret, &chain, CFSwapInt32LittleToHost(hash.u32[0]) | BIP32_HARD); // m/13H/aH
    CKDpriv(&secret, &chain, CFSwapInt32LittleToHost(hash.u32[1]) | BIP32_HARD); // m/13H/aH/bH
    CKDpriv(&secret, &chain, CFSwapInt32LittleToHost(hash.u32[2]) | BIP32_HARD); // m/13H/aH/bH/cH
    CKDpriv(&secret, &chain, CFSwapInt32LittleToHost(hash.u32[3]) | BIP32_HARD); // m/13H/aH/bH/cH/dH

    NSMutableData *privKey = [NSMutableData secureDataWithCapacity:34];
    
    [privKey appendBytes:&version length:1];
    [privKey appendBytes:&secret length:sizeof(secret)];
    [privKey appendBytes:"\x01" length:1]; // specifies compressed pubkey format
//    NSLog(@"TESTB_base58checkWithData:privKey : %@", [NSString base58checkWithData:privKey]); //t
    return [NSString base58checkWithData:privKey];
}

// MARK: - serializations

- (NSString *)serializedPrivateMasterFromSeed:(NSData *)seed
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(serializedPrivateMasterFromSeed)"); //a
    if (! seed) return nil;

    UInt512 I;

    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);

    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];

//    NSLog(@"TEST_serializedPrivateMasterFromSeed : %@", serialize(0, 0, 0, chain, [NSData dataWithBytes:&secret length:sizeof(secret)])); //t
    
    return serialize(0, 0, 0, chain, [NSData dataWithBytes:&secret length:sizeof(secret)]);
    

}

- (NSString *)serializedMasterPublicKey:(NSData *)masterPublicKey
{
//    NSLog(@"Call_BRBIP32Sequence.m Method(serializedMasterPublicKey)"); //a
    if (masterPublicKey.length < 36) return nil;
    
    uint32_t fingerprint = CFSwapInt32BigToHost(*(const uint32_t *)masterPublicKey.bytes);
    UInt256 chain = *(UInt256 *)((const uint8_t *)masterPublicKey.bytes + 4);
    BRECPoint pubKey = *(BRECPoint *)((const uint8_t *)masterPublicKey.bytes + 36);

//    NSLog(@"TEST_serializedMasterPublicKey : %@", serialize(1, fingerprint, 0 | BIP32_HARD, chain, [NSData dataWithBytes:&pubKey length:sizeof(pubKey)])); //t
    
    return serialize(1, fingerprint, 0 | BIP32_HARD, chain, [NSData dataWithBytes:&pubKey length:sizeof(pubKey)]);
}

@end
