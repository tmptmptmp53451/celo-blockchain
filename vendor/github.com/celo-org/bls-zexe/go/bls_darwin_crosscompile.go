// +build crosscompile, darwin,386

package bls

/*
#cgo LDFLAGS: -L../bls/target/i686-apple-darwin/release -lbls_zexe -lbls_snark -ldl -lm
*/
import "C"
