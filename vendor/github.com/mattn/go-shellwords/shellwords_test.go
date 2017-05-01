package shellwords

import (
	"os"
	"reflect"
	"testing"
)

var testcases = []struct {
	line     string
	expected []string
}{
	{`var --bar=baz`, []string{`var`, `--bar=baz`}},
	{`var --bar="baz"`, []string{`var`, `--bar=baz`}},
	{`var "--bar=baz"`, []string{`var`, `--bar=baz`}},
	{`var "--bar='baz'"`, []string{`var`, `--bar='baz'`}},
	{"var --bar=`baz`", []string{`var`, "--bar=`baz`"}},
	{`var "--bar=\"baz'"`, []string{`var`, `--bar="baz'`}},
	{`var "--bar=\'baz\'"`, []string{`var`, `--bar='baz'`}},
	{`var --bar='\'`, []string{`var`, `--bar=\`}},
	{`var "--bar baz"`, []string{`var`, `--bar baz`}},
	{`var --"bar baz"`, []string{`var`, `--bar baz`}},
	{`var  --"bar baz"`, []string{`var`, `--bar baz`}},
}

func TestSimple(t *testing.T) {
	for _, testcase := range testcases {
		args, err := Parse(testcase.line)
		if err != nil {
			t.Fatalf(err.Error())
		}
		if !reflect.DeepEqual(args, testcase.expected) {
			t.Fatalf("Expected %v, but %v:", testcase.expected, args)
		}
	}
}

func TestError(t *testing.T) {
	_, err := Parse("foo '")
	if err == nil {
		t.Fatalf("Should be an error")
	}
	_, err = Parse(`foo "`)
	if err == nil {
		t.Fatalf("Should be an error")
	}

	_, err = Parse("foo `")
	if err == nil {
		t.Fatalf("Should be an error")
	}
}

func TestBacktick(t *testing.T) {
	goversion, err := shellRun("go version")
	if err != nil {
		t.Fatalf(err.Error())
	}

	parser := NewParser()
	parser.ParseBacktick = true
	args, err := parser.Parse("echo `go version`")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := []string{"echo", goversion}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Expected %v, but %v:", expected, args)
	}
}

func TestBacktickError(t *testing.T) {
	parser := NewParser()
	parser.ParseBacktick = true
	_, err := parser.Parse("echo `go Version`")
	if err == nil {
		t.Fatalf("Should be an error")
	}
}

func TestEnv(t *testing.T) {
	os.Setenv("FOO", "bar")

	parser := NewParser()
	parser.ParseEnv = true
	args, err := parser.Parse("echo $FOO")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := []string{"echo", "bar"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Expected %v, but %v:", expected, args)
	}
}

func TestNoEnv(t *testing.T) {
	parser := NewParser()
	parser.ParseEnv = true
	args, err := parser.Parse("echo $BAR")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := []string{"echo", ""}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Expected %v, but %v:", expected, args)
	}
}

func TestDupEnv(t *testing.T) {
	os.Setenv("FOO", "bar")
	os.Setenv("FOO_BAR", "baz")

	parser := NewParser()
	parser.ParseEnv = true
	args, err := parser.Parse("echo $$FOO$")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected := []string{"echo", "$bar$"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Expected %v, but %v:", expected, args)
	}

	args, err = parser.Parse("echo $${FOO_BAR}$")
	if err != nil {
		t.Fatalf(err.Error())
	}
	expected = []string{"echo", "$baz$"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("Expected %v, but %v:", expected, args)
	}
}
