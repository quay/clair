//go:build ignore
// +build ignore

package main

import (
	"encoding/json"
	"html/template"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("history: ")

	// Handle when called with "supports $renderer".
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "supports":
			switch os.Args[2] {
			case "html":
			default:
				os.Exit(1)
			}
		default:
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Actual preprocessing mode.
	log.Println("running preprocessor")

	in := make([]json.RawMessage, 2)
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		panic(err)
	}
	var cfg Config
	if err := json.Unmarshal(in[0], &cfg); err != nil {
		panic(err)
	}
	var book Book
	if err := json.Unmarshal(in[1], &book); err != nil {
		panic(err)
	}

	var b strings.Builder
	for _, s := range book.Sections {
		if err := s.Process(&b, &cfg, tmpl); err != nil {
			panic(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
		panic(err)
	}
}

// in: {"root":"/var/home/hank/work/clair/clair","config":{"book":{"authors":["Clair Authors"],"description":"Documentation for Clair.","language":"en","multilingual":false,"src":"Documentation","title":"Clair Documentation"},"output":{"html":{"git-repository-url":"https://github.com/quay/clair","preferred-dark-theme":"coal"}},"preprocessor":{"history":{"command":"go run Documentation/history.go"}}},"renderer":"html","mdbook_version":"0.4.13"}
type Config struct {
	Root     string `json:"root"`
	Renderer string `json:"renderer"`
	Version  string `json:"mdbook_version"`
	Config   struct {
		Book BookConfig `json:"book"`
	} `json:"config"`
}

type BookConfig struct {
	Source string `json:"src"`
}

type Book struct {
	Sections []Section `json:"sections"`
	X        *struct{} `json:"__non_exhaustive"`
}

type Section struct {
	Chapter   *Chapter    `json:",omitempty"`
	Separator interface{} `json:",omitempty"`
	PartTitle string      `json:",omitempty"`
}

func (s *Section) Process(b *strings.Builder, cfg *Config, t *template.Template) error {
	if s.Chapter != nil {
		return s.Chapter.Process(b, cfg, t)
	}
	return nil
}

type Chapter struct {
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	Number      []int     `json:"number"`
	SubItems    []Section `json:"sub_items"`
	Path        *string   `json:"path"`
	SourcePath  *string   `json:"source_path"`
	ParentNames []string  `json:"parent_names"`
}

func (c *Chapter) Process(b *strings.Builder, cfg *Config, t *template.Template) error {
	if marker.MatchString(c.Content) && c.Path != nil {
		log.Println("inserting history into:", *c.Path)
		cmd := exec.Command(`git`, `log`, `--reverse`, "--format=%cs\t%s", `--`, filepath.Join(cfg.Root, cfg.Config.Book.Source, *c.Path))
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		var ls []Line
		for _, l := range strings.FieldsFunc(string(out), func(r rune) bool { return r == '\n' }) {
			s := strings.SplitN(l, "\t", 2)
			ls = append(ls, Line{Date: s[0], Summary: s[1]})
		}
		b.Reset()
		if err := t.ExecuteTemplate(b, cfg.Renderer, ls); err != nil {
			return err
		}
		c.Content = marker.ReplaceAllString(c.Content, b.String())
	}
	for _, s := range c.SubItems {
		if err := s.Process(b, cfg, t); err != nil {
			return err
		}
	}
	return nil
}

type Line struct {
	Date    string
	Summary string
}

var (
	tmpl   *template.Template
	marker = regexp.MustCompile(`\{\{#\s*history\s*\}\}`)
)

func init() {
	const (
		html = `<details>
<summary>Document History</summary>
<p><ul>
{{ range . }}<li><strong>{{.Date}}</strong> {{.Summary}}</li>
{{ end }}</ul></p>
</details>`
	)
	tmpl = template.New("")
	template.Must(tmpl.New("html").Parse(html))
}
