package keccaklookup

import "fmt"

func checkLen[T any](arr []T, length int) {
	if len(arr) != length {
		panic(fmt.Sprintf("arr len %d, expected %d", len(arr), length))
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func parseBinary(bs string) Word {
	var sum uint64 = 0
	for i, c := range bs {
		var d uint64 = 0
		if c == '1' {
			d = 1
		}
		sum += d << (len(bs) - 1 - i)
	}
	return Word{Val: sum, Size: len(bs)}
}
