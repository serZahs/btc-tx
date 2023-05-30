package main

import (
	"fmt"
)

type byte_vector []byte

type Stack struct {
	items [10]byte_vector
	pos   int
}

func stack_push(stack *Stack, data []byte) {
	stack.items[stack.pos] = data
	stack.pos += 1
}

func stack_pop(stack *Stack) byte_vector {
	stack.pos -= 1
	res := stack.items[stack.pos]
	stack.items[stack.pos] = nil
	return res
}

func stack_peek(stack *Stack) byte_vector {
	return stack.items[stack.pos-1]
}

func stack_print(stack *Stack) {
	for i := 0; i < stack.pos; i++ {
		fmt.Printf("--> %x\n", stack.items[i])
	}
}
