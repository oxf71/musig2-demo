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


## taproot musig2 example

```shell
➜  musig2-demo git:(main) ✗ go run example/taprootmusig/main.go 
utxoTaprootAddress: tb1prggx0jcdqgag2kj9agxa7n6p888ffpzs4flps8ztwctrluz040hq6x9sz8
musigAddress no script: tb1pegcl5gc8d9smtux47ezk7fa85jk3tu48e0920d3pqrffq8jfc3gs2l0fgy
unspentList: 73a20bf212b60e191ae6808ad921d1080eb28cfe5049b98c4ff9457e4e44fe57:1
unspentList: 92851308a20a38944728baf496476a568d13131e622f7f34c80729ab2c17b750:0
musig commitAddress: tb1pz5n2kes9edrgvhuety8n38q55nvxfmdew7e0e76dt93sdc2scunqj96wjz
taproot sign
2024/01/07 13:55:02 recoveryKeyWIF 0 cVPr3q8FLH5GxGUWtFxGspH8zM1ojLaXw3R4asWurXZVA41rn5oD 
2024/01/07 13:55:02 commitTxHex 0100000000010257fe444e7e45f94f8cb94950fe8cb20e08d121d98a80e61a190eb612f20ba2730100000000f5ffffff50b7172cab2907c8347f2f621e13138d566a4796f4ba284794380aa2081385920000000000f5ffffff02a40c0000000000002251201526ab6605cb46865f99590f389c14a4d864edb977b2fcfb4d596306e150c72674700f00000000002251201a1067cb0d023a855a45ea0ddf4f4139ce948450aa7e181c4b76163ff04fabee01406b12417046297c390979167972a3dc107dc1dc932dd20d26774ed76cee6489c1a5eb7052c19c270db8baea10ed80b9979430231dded835a420e34dbfb264198f0140451786067ed3692fbdfe29eece6c97a8349fa9b0a3bd8956068fee160394b186535bf9c91a95921dc272c73bbcbd30ed9d19567a9708fc52b299fddc7fa7d37200000000 
2024/01/07 13:55:02 revealTxHex 0 0100000000010159ec22c8f36a62f3c7d3ecea32060d81d751d176e68ce0ef50a49acb870160c90000000000f5ffffff01f4010000000000002251201a1067cb0d023a855a45ea0ddf4f4139ce948450aa7e181c4b76163ff04fabee0340f0013735c53d4ae47698b961b872ab774440fb84faac348d6dad66fea222b0fd566a29dd533d4c55ec2fce910f6ce4398c5a478acf5266d0ef6f98dbb460f05c5f20c3b383df58f16de1f5317cbcff2232dd2e99f79d53cd5777faaf06314d375cb2ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38001943726561746520576974686f75742066756c6c204e6f6465206821c1c3b383df58f16de1f5317cbcff2232dd2e99f79d53cd5777faaf06314d375cb200000000 
commitTx json marshal: {"Version":1,"TxIn":[{"PreviousOutPoint":{"Hash":"73a20bf212b60e191ae6808ad921d1080eb28cfe5049b98c4ff9457e4e44fe57","Index":1},"SignatureScript":null,"Witness":["axJBcEYpfDkJeRZ5cqPcEH3B3JMt0g0md07XbO5kicGl63BSwZwnDbi66hDtgLmXlDAjHd7YNaQg402/smQZjw=="],"Sequence":4294967285},{"PreviousOutPoint":{"Hash":"92851308a20a38944728baf496476a568d13131e622f7f34c80729ab2c17b750","Index":0},"SignatureScript":null,"Witness":["RReGBn7TaS+9/inuzmyXqDSfqbCjvYlWBo/uFgOUsYZTW/nJGpWSHcJyxzu8vTDtnRlWepcI/FKymf3cf6fTcg=="],"Sequence":4294967285}],"TxOut":[{"Value":3236,"PkScript":"USAVJqtmBctGhl+ZWQ84nBSk2GTtuXey/PtNWWMG4VDHJg=="},{"Value":1011828,"PkScript":"USAaEGfLDQI6hVpF6g3fT0E5zpSEUKp+GBxLdhY/8E+r7g=="}],"LockTime":0}
revealTx json marshal: [{"Version":1,"TxIn":[{"PreviousOutPoint":{"Hash":"c9600187cb9aa450efe08ce676d151d7810d0632eaecd3c7f3626af3c822ec59","Index":0},"SignatureScript":null,"Witness":["8AE3NcU9SuR2mLlhuHKrd0RA+4T6rDSNba1m/qIisP1WaindUz1MVewvzpEPbOQ5jFpHis9SZtDvb5jbtGDwXA==","IMOzg99Y8W3h9TF8vP8iMt0umfedU81Xd/qvBjFNN1yyrABjA29yZAEBGHRleHQvcGxhaW47Y2hhcnNldD11dGYtOAAZQ3JlYXRlIFdpdGhvdXQgZnVsbCBOb2RlIGg=","wcOzg99Y8W3h9TF8vP8iMt0umfedU81Xd/qvBjFNN1yy"],"Sequence":4294967285}],"TxOut":[{"Value":500,"PkScript":"USAaEGfLDQI6hVpF6g3fT0E5zpSEUKp+GBxLdhY/8E+r7g=="}],"LockTime":0}]
2024/01/07 13:55:02 commitTxHash, c9600187cb9aa450efe08ce676d151d7810d0632eaecd3c7f3626af3c822ec59
2024/01/07 13:55:02 revealTxHash, 12eee7681ce5e9af5db26a655aeb5849fbbb25a027ae251628c2946fab01214e
2024/01/07 13:55:02 inscription, 12eee7681ce5e9af5db26a655aeb5849fbbb25a027ae251628c2946fab01214ei0
2024/01/07 13:55:02 fees:  5940
➜  musig2-demo git:(main) ✗ 
```



## notice

btcec(v2.3.2 )musig2 use EarlyNonceGen failed 


musig2 context bug, The fixed code is still on the master branch

https://github.com/btcsuite/btcd/commit/8f84bb0e9bcbdc1dfc00c5d35382927a8a6edd8e  

