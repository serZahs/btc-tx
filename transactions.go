package main

import (
	"bytes"
	"encoding/binary"
	"errors"
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
