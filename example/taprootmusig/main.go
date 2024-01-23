package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/oxf71/musig2-demo/lib/go-ord-tx/pkg/btcapi/mempool"
	"github.com/oxf71/musig2-demo/lib/go-ord-tx/pkg/ord"
	"github.com/oxf71/musig2-demo/psbt"
)

func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}
func main() {
	netParams := &chaincfg.TestNet3Params
	btcApiClient := mempool.NewClient(netParams)
	privKey1, publicKey1 := btcec.PrivKeyFromBytes(decodeHex("440bb3ec56d213e90d006d344d74f6478db4f7fa4cdd388095d8f4edef0c5156"))
	privKey2, publicKey2 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa778"))
	_, publicKey3 := btcec.PrivKeyFromBytes(decodeHex("e0087817fd1d1154a781c11b394a0dcec82f076bbf026df9d61667ead16fa771"))
	publicKey1Hex := hex.EncodeToString(publicKey1.SerializeCompressed())
	publicKey2Hex := hex.EncodeToString(publicKey2.SerializeCompressed())
	publicKey3Hex := hex.EncodeToString(publicKey3.SerializeCompressed())
	allSignerPubKeys := []string{publicKey1Hex, publicKey2Hex, publicKey3Hex}
	// gen 2-3 multi address

	multiTaprootAddress, multiScript, err := psbt.GenerateMultiTaprootAddress(allSignerPubKeys, 2, netParams)
	if err != nil {
		log.Fatal(err)
	}

	musigPriv := make([]*btcec.PrivateKey, 0)
	musigPriv = append(musigPriv, privKey1, privKey2)

	musigAddress, _ := btcutil.DecodeAddress(multiTaprootAddress, netParams)

	fmt.Println("segwit musigAddress no script:", musigAddress.EncodeAddress())

	unspentList, err := btcApiClient.ListUnspent(musigAddress)
	if err != nil {
		log.Fatalf("list unspent err %v", err)
	}

	if len(unspentList) == 0 {
		log.Fatal("no unspent")
	}

	commitTxOutPointList := make([]*wire.OutPoint, 0)
	commitTxPrivateKeyList := make([]*btcec.PrivateKey, 0)
	for i := range unspentList {
		commitTxOutPointList = append(commitTxOutPointList, unspentList[i].Outpoint)
		commitTxPrivateKeyList = append(commitTxPrivateKeyList, privKey1)
		fmt.Println("unspentList:", unspentList[i].Outpoint)
		fmt.Println("unspentList out:", unspentList[i].Output)
	}

	dataList := make([]ord.InscriptionData, 0)

	dataList = append(dataList, ord.InscriptionData{
		ContentType: "text/plain;charset=utf-8",
		Body:        []byte(`{"p":"brc-20","op":"transfer","tick":"ston","amt":"8"}`),
		Destination: "tb1qhnqzre2a9mg045mze6syjc84h9qr9us0rpypf4r8dc8ndxc4l2sslj7u8t",
	})

	request := ord.InscriptionRequest{
		CommitTxOutPointList:   commitTxOutPointList,
		CommitTxPrivateKeyList: commitTxPrivateKeyList,
		CommitFeeRate:          18,
		FeeRate:                19,
		DataList:               dataList,
		SingleRevealTxOnly:     false,
		MultiScript:            multiScript,
		MultiPriv:              musigPriv,
	}

	tool, err := ord.NewInscriptionToolWithBtcApiClient(netParams, btcApiClient, &request, musigPriv)
	if err != nil {
		log.Fatalf("Failed to create inscription tool: %v", err)
	}
	recoveryKeyWIFList := tool.GetRecoveryKeyWIFList()
	for i, recoveryKeyWIF := range recoveryKeyWIFList {
		log.Printf("recoveryKeyWIF %d %s \n", i, recoveryKeyWIF)
	}

	commitTxHex, err := tool.GetCommitTxHex()
	if err != nil {
		log.Fatalf("get commit tx hex err, %v", err)
	}
	log.Printf("commitTxHex %s \n", commitTxHex)
	revealTxHexList, err := tool.GetRevealTxHexList()
	if err != nil {
		log.Fatalf("get reveal tx hex err, %v", err)
	}
	for i, revealTxHex := range revealTxHexList {
		log.Printf("revealTxHex %d %s \n", i, revealTxHex)
	}
	commitTxHash, revealTxHashList, inscriptions, fees, err := tool.Inscribe()
	if err != nil {
		log.Fatalf("send tx errr, %v", err)
	}
	log.Println("commitTxHash, " + commitTxHash.String())
	for i := range revealTxHashList {
		log.Println("revealTxHash, " + revealTxHashList[i].String())
	}
	for i := range inscriptions {
		log.Println("inscription, " + inscriptions[i])
	}
	log.Println("fees: ", fees)
}
