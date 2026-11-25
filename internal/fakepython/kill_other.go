//go:build !unix

package fakepython

func killSelf() int { return 104 }
