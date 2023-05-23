package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

func RunScript(script []byte) error {
	//fmt.Printf("%x\n", script)
	var stack Stack
	stack_init(&stack)
	for i := 0; i < len(script); i++ {
		switch b := script[i]; b {
		case 0x76:
			fmt.Println("OP_DUP")
			top := stack_peek(&stack)
			stack_push(&stack, top)
		case 0x88:
			fmt.Println("OP_EQUALVERIFY")
			x1 := stack_pop(&stack)
			x2 := stack_pop(&stack)
			result := bytes.Equal(x1, x2)
			if !result {
				return errors.New("transaction validation failed")
			}
			stack_print(&stack)
		case 0xa9:
			fmt.Println("OP_HASH160")
			top := stack_pop(&stack)
			stack_push(&stack, Hash160(top))
		case 0xac:
			fmt.Println("OP_CHECKSIG")
			return nil
		default:
			if b >= 0x01 && b <= 0x4b {
				fmt.Println("OP_PUSHDATA0")
				stack_push(&stack, script[i+1:i+int(b)+1])
				i += int(b)
			} else {
				return errors.New("opcode not supported")
			}
		}
	}
	return nil
}
