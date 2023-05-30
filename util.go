package main

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func Hash160(buffer []byte) []byte {
	sha_hash := sha256.New()
	ripemd_hash := ripemd160.New()

	sha_hash.Write(buffer)
	ripemd_hash.Write(sha_hash.Sum(nil))
	return ripemd_hash.Sum(nil)
}

func ComputeChecksum(data []byte) []byte {
	first := sha256.New()
	second := sha256.New()

	first.Write(data)
	second.Write(first.Sum(nil))
	return second.Sum(nil)
}

func EncodeAddress(public_key_hash []byte) (string, error) {
	if len(public_key_hash) != 20 {
		return "", errors.New("the public key hash must be 20 bytes")
	}
	var unencoded_address [25]byte
	unencoded_address[0] = 0x00 // Version byte (P2PKH)
	copy(unencoded_address[1:], public_key_hash[:])
	checksum := ComputeChecksum(unencoded_address[:21])
	copy(unencoded_address[21:], checksum[:4])
	encoded := base58.Encode(unencoded_address[:])
	return encoded, nil
}

func DecodeAddress(address string) ([]byte, error) {
	decoded := base58.Decode(address)
	public_key_hash := decoded[1 : len(decoded)-4]
	if len(public_key_hash) != 20 {
		return nil, errors.New("the address format is incorrect")
	}
	return public_key_hash, nil
}
