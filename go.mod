module github.com/oxf71/musig2-demo

go 1.21.4

require (
	github.com/btcsuite/btcd v0.24.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/pkg/errors v0.9.1
	github.com/taurusgroup/multi-party-sig v0.6.0-alpha-2021-09-21
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/cronokirby/safenum v0.29.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v3 v3.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.3.0 // indirect
	github.com/kkdai/bstream v0.0.0-20161212061736-f391b8402d23 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	golang.org/x/sys v0.0.0-20210820121016-41cdb8703e55 // indirect
)

replace github.com/btcsuite/btcd/btcec/v2 => ./lib/btcd/btcec
