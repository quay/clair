package kingpin

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatTwoColumns(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	formatTwoColumns(buf, 2, 2, 20, [][2]string{
		{"--hello", "Hello world help with something that is cool."},
	})
	expected := `  --hello  Hello
           world
           help with
           something
           that is
           cool.
`
	assert.Equal(t, expected, buf.String())
}

func TestFormatTwoColumnsWide(t *testing.T) {
	samples := [][2]string{
		{strings.Repeat("x", 19), "19 chars"},
		{strings.Repeat("x", 20), "20 chars"}}
	buf := bytes.NewBuffer(nil)
	formatTwoColumns(buf, 0, 0, 200, samples)
	fmt.Println(buf.String())
	expected := `xxxxxxxxxxxxxxxxxxx19 chars
xxxxxxxxxxxxxxxxxxxx
                   20 chars
`
	assert.Equal(t, expected, buf.String())
}
