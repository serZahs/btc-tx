package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/dustinxie/ecc"
)

type compact_size int64

type Transaction struct {
	version      int32
	input_count  compact_size
	inputs       []Transaction_Input
	output_count int64
	outputs      []Transaction_Output
	lock_time    uint32
}

type Transaction_Output struct {
	amount      int64
	script_size compact_size
	script      []byte // Locking script
}

type Transaction_Input struct {
	transaction_hash [32]byte
	output_index     uint32
	script_size      compact_size
	script           []byte // Unlocking script
	sequence         uint32
}

const (
	OP_DUP         = 0x76
	OP_EQUALVERIFY = 0x88
	OP_HASH160     = 0xa9
	OP_CHECKSIG    = 0xac
)

func DeserializeTransaction(raw_data []byte) (*Transaction, error) {
	var t Transaction

	// Read version
	index := 4
	binary.Read(bytes.NewReader(raw_data[0:index]), binary.LittleEndian, &t.version)

	// Read count of inputs
	input_count := raw_data[index]
	if input_count > 0xfc {
		return nil, errors.New("variable length sizes not supported yet")
	}
	binary.Read(bytes.NewReader([]byte{raw_data[index], 0, 0, 0, 0, 0, 0, 0}), binary.LittleEndian, &t.input_count)
	index += 1

	// Read inputs
	for i := 0; i < int(t.input_count); i++ {
		var input Transaction_Input
		for i := 31; i >= 0; i-- {
			input.transaction_hash[i] = raw_data[index]
			index += 1
		}
		binary.Read(bytes.NewReader(raw_data[index:index+4]), binary.LittleEndian, &input.output_index)
		index += 4

		script_size := raw_data[index]
		if script_size > 0xfc {
			return nil, errors.New("variable length sizes not supported yet")
		}
		binary.Read(bytes.NewReader([]byte{raw_data[index], 0, 0, 0, 0, 0, 0, 0}), binary.LittleEndian, &input.script_size)
		index += 1
		input.script = append(input.script, raw_data[index:index+int(input.script_size)]...)
		index += int(input.script_size)
		binary.Read(bytes.NewReader(raw_data[index:index+4]), binary.LittleEndian, &input.sequence)
		index += 4
		t.inputs = append(t.inputs, input)
	}
	/*for i, v := range t.inputs {
		fmt.Printf("%d [%x] %x %x [%x] %x\n", i, v.transaction_hash, v.output_index, v.script_size, v.script, v.sequence)
	}*/

	// Read count of outputs
	output_count := raw_data[index]
	if output_count > 0xfc {
		return nil, errors.New("variable length sizes not supported yet")
	}
	binary.Read(bytes.NewReader([]byte{raw_data[index], 0, 0, 0, 0, 0, 0, 0}), binary.LittleEndian, &t.output_count)
	index += 1

	// Read outputs
	for i := 0; i < int(t.output_count); i++ {
		var output Transaction_Output
		binary.Read(bytes.NewReader(raw_data[index:index+8]), binary.LittleEndian, &output.amount)
		index += 8

		script_size := raw_data[index]
		if script_size > 0xfc {
			return nil, errors.New("variable length sizes not supported yet")
		}
		binary.Read(bytes.NewReader([]byte{raw_data[index], 0, 0, 0, 0, 0, 0, 0}), binary.LittleEndian, &output.script_size)
		index += 1
		output.script = append(output.script, raw_data[index:index+int(output.script_size)]...)
		index += int(output.script_size)
		t.outputs = append(t.outputs, output)
	}
	/*for i, v := range t.outputs {
		fmt.Printf("%d %x %x [%x]\n", i, v.amount, v.script_size, v.script)
	}*/

	// Read locktime
	binary.Read(bytes.NewReader(raw_data[index:index+4]), binary.LittleEndian, &t.lock_time)
	index += 4

	return &t, nil
}

func SerializeTransaction(t Transaction) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)

	binary.Write(buffer, binary.LittleEndian, t.version)

	if t.input_count > 0xfc {
		return nil, errors.New("variable length sizes not supported yet")
	}
	binary.Write(buffer, binary.LittleEndian, byte(t.input_count))

	for _, v := range t.inputs {
		for i := 31; i >= 0; i-- {
			binary.Write(buffer, binary.LittleEndian, v.transaction_hash[i])
		}
		binary.Write(buffer, binary.LittleEndian, v.output_index)

		if v.script_size > 0xfc {
			return nil, errors.New("variable length sizes not supported yet")
		}
		binary.Write(buffer, binary.LittleEndian, byte(v.script_size))
		if v.script_size != 0x00 {
			binary.Write(buffer, binary.LittleEndian, v.script)
		}
		binary.Write(buffer, binary.LittleEndian, v.sequence)
	}

	if t.output_count > 0xfc {
		return nil, errors.New("variable length sizes not supported yet")
	}
	binary.Write(buffer, binary.LittleEndian, byte(t.output_count))

	for _, v := range t.outputs {
		binary.Write(buffer, binary.LittleEndian, v.amount)
		if v.script_size > 0xfc {
			return nil, errors.New("variable length sizes not supported yet")
		}
		binary.Write(buffer, binary.LittleEndian, byte(v.script_size))
		if v.script_size != 0x00 {
			binary.Write(buffer, binary.LittleEndian, v.script)
		}
	}

	binary.Write(buffer, binary.LittleEndian, t.lock_time)

	return buffer.Bytes(), nil
}

func ValidateTransactionScript(tx_new Transaction, tx_prev Transaction, input_index int) error {
	output_index := tx_new.inputs[input_index].output_index
	subscript := tx_prev.outputs[output_index].script

	script := tx_new.inputs[input_index].script
	script = append(script, subscript...)

	var stack Stack
	for i := 0; i < len(script); i++ {
		switch b := script[i]; b {
		case OP_DUP:
			//fmt.Println("OP_DUP")
			top := stack_peek(&stack)
			stack_push(&stack, top)
		case OP_EQUALVERIFY:
			//fmt.Println("OP_EQUALVERIFY")
			x1 := stack_pop(&stack)
			x2 := stack_pop(&stack)
			result := bytes.Equal(x1, x2)
			if !result {
				return errors.New("transaction validation failed")
			}
		case OP_HASH160:
			//fmt.Println("OP_HASH160")
			top := stack_pop(&stack)
			stack_push(&stack, Hash160(top))
		case OP_CHECKSIG:
			//fmt.Println("OP_CHECKSIG")
			public_key := stack_pop(&stack)
			signature := stack_pop(&stack)

			index := 3
			r_length := signature[index]
			index += 1
			r_bytes := signature[index : index+int(r_length)]
			index += int(r_length) + 1
			s_length := signature[index]
			index += 1
			s_bytes := signature[index : index+int(s_length)]
			index += int(s_length)
			sig_hash := signature[index]

			if sig_hash != 0x01 {
				return errors.New("only SIGHASH_ALL is supported")
			}

			r := new(big.Int).SetBytes(r_bytes)
			s := new(big.Int).SetBytes(s_bytes)

			for i := range tx_new.inputs {
				v := &tx_new.inputs[i]
				if i == input_index {
					v.script_size = compact_size(len(subscript))
					v.script = subscript
				} else {
					v.script_size = 0x00
					v.script = nil
				}
			}

			serialized, err := SerializeTransaction(tx_new)
			if err != nil {
				return err
			}
			serialized = append(serialized, []byte{sig_hash, 0, 0, 0}...)

			hashed := sha256.Sum256(serialized)
			hashed = sha256.Sum256(hashed[:])

			curve := ecc.P256k1()
			x, y := elliptic.Unmarshal(curve, public_key)
			pk := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

			if ecdsa.Verify(&pk, hashed[:], r, s) {
				stack_push(&stack, []byte{1})
			} else {
				stack_push(&stack, []byte{0})
			}
		default:
			if b >= 0x01 && b <= 0x4b {
				//fmt.Println("OP_PUSHDATA0")
				stack_push(&stack, script[i+1:i+int(b)+1])
				i += int(b)
			} else {
				return errors.New("opcode not supported")
			}
		}
	}
	if stack.pos > 0 {
		val := stack_pop(&stack)
		if val[0] == 0 {
			return errors.New("transaction validation failed")
		}
	}
	return nil
}
