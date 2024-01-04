## musig2 


sig opt

- [x] 1. early nonce gen
- [ ] 2. taproot_bip_86
- [ ] 3. taproot_tweaked_x_only
- [ ] 4. tweaked_x_only
- [ ] 5. tweaked


## usage

 


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



## notice

btcec(v2.3.2 )musig2 use EarlyNonceGen failed 


musig2 context bug, The fixed code is still on the master branch

https://github.com/btcsuite/btcd/commit/8f84bb0e9bcbdc1dfc00c5d35382927a8a6edd8e  

