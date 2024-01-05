## musig2 


sig opt

- [x] 1. early nonce gen
- [ ] 2. taproot_bip_86
- [ ] 3. taproot_tweaked_x_only
- [ ] 4. tweaked_x_only
- [ ] 5. tweaked



// TaprootTweak specifies that the final key should use the taproot
// tweak as defined in BIP 341:
//     outputKey = internalKey + h_tapTweak(internalKey || scriptRoot).
// In this case, the aggregated key before the tweak will be used as the
// internal key. Will be ignored if TaprootBIP0086Tweak is set to true.

## usage

 
early nonce gen

```go
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[0].secretKey))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex(bip340TestVectors[1].secretKey))

	musig2_early_demo()
	msg := []byte("msg hello")
	sign, hash, err := musig2demo.TwoPrivSign2(privKey1, privKey2, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sign: ", hex.EncodeToString(sign.Serialize()))
	fmt.Println("sign hash", hex.EncodeToString(hash))

	btcAddress := musig2demo.TwoBtcAddress(privKey1, privKey2)
	fmt.Println("btcAddress: ", btcAddress)

	taprootAddress := musig2demo.TwoBtcTaprootAddress(privKey1, privKey2)
	fmt.Println("taprootAddress: ", taprootAddress)

	// verify sign

	combinedKey, err := musig2demo.TwoCombinedKey(privKey1, privKey2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("combinedKey", combinedKey.SerializeCompressed())

	fmt.Println("sign verify: ", sign.Verify(hash, combinedKey))

```


taproot_tweaked_x_only

```go
	privKey1, _ := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, _ := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	testTweak := [32]byte{
		0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
		0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
		0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
		0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
	}

	priv := []*btcec.PrivateKey{privKey1, privKey2}

	sign, combinedKey, hash, err := musig2demo.MultiPartySign(priv, testTweak[:], []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
```



## notice

btcec(v2.3.2 )musig2 use EarlyNonceGen failed 


musig2 context bug, The fixed code is still on the master branch

https://github.com/btcsuite/btcd/commit/8f84bb0e9bcbdc1dfc00c5d35382927a8a6edd8e  

