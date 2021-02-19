package codec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Example() {
	enc := GetEncoder(os.Stdout)
	defer PutEncoder(enc)
	enc.MustEncode([]string{"a", "slice", "of", "strings"})
	fmt.Fprintln(os.Stdout)
	enc.MustEncode(nil)
	fmt.Fprintln(os.Stdout)
	enc.MustEncode(map[string]string{})
	fmt.Fprintln(os.Stdout)
	// Output: ["a","slice","of","strings"]
	// null
	// {}
}

func BenchmarkDecode(b *testing.B) {
	b.ReportAllocs()
	want := map[string]string{
		"a": strings.Repeat(`A`, 2048),
		"b": strings.Repeat(`B`, 2048),
		"c": strings.Repeat(`C`, 2048),
		"d": strings.Repeat(`D`, 2048),
	}
	got := make(map[string]string, len(want))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dec := GetDecoder(JSONReader(want))
		err := dec.Decode(&got)
		PutDecoder(dec)
		if err != nil {
			b.Error(err)
		}
		if !cmp.Equal(got, want) {
			b.Error(cmp.Diff(got, want))
		}
	}
}

func BenchmarkDecodeStdlib(b *testing.B) {
	b.ReportAllocs()
	want := map[string]string{
		"a": strings.Repeat(`A`, 2048),
		"b": strings.Repeat(`B`, 2048),
		"c": strings.Repeat(`C`, 2048),
		"d": strings.Repeat(`D`, 2048),
	}
	got := make(map[string]string, len(want))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		x, err := json.Marshal(want)
		if err != nil {
			b.Error(err)
		}
		if err := json.Unmarshal(x, &got); err != nil {
			b.Error(err)
		}
		if !cmp.Equal(got, want) {
			b.Error(cmp.Diff(got, want))
		}
	}
}
