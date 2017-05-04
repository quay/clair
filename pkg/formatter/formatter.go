package formatter

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

// JSONExtendedFormatter formats log information to JSON format with time and line number in file
type JSONExtendedFormatter struct {
	ShowLn bool
}

func (f *JSONExtendedFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Because entry.Data is not concurrent write safe, we need to copy the dictionary
	data := make(logrus.Fields, len(entry.Data)+4)

	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/Sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	if f.ShowLn {
		var (
			filename = "???"
			filepath string
			line     int
			ok       = true
		)
		// worst case is O(call stack size)
		for depth := 3; ok; depth++ {
			_, filepath, line, ok = runtime.Caller(depth)
			if !ok {
				line = 0
				filename = "???"
				break
			} else if !strings.Contains(filepath, "logrus") {
				if line < 0 {
					line = 0
				}
				slash := strings.LastIndex(filepath, "/")
				if slash >= 0 {
					filename = filepath[slash+1:]
				} else {
					filename = filepath
				}
				break
			}
		}
		data["Location"] = fmt.Sprintf("%s:%d", filename, line)
	}
	now := entry.Time
	ts := now.Format("2006-01-02 15:04:05")
	ms := now.Nanosecond() / 1000

	data["Time"] = fmt.Sprintf("%s.%06d", ts, ms)
	data["Event"] = entry.Message
	data["Level"] = entry.Level.String()

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}
