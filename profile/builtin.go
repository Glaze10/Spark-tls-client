package profile

import (
	"embed"
	"path"
	"strings"
)

//go:embed builtin/*.json
var builtinFS embed.FS

var builtin = map[string]*Profile{}

var aliases = map[string]string{
	"chrome":        "chrome-151-windows",
	"chrome-151":    "chrome-151-windows",
	"chrome-latest": "chrome-151-windows",
	"ios":           "ios-safari-26",
	"ios-latest":    "ios-safari-26",
	"safari-ios":    "ios-safari-26",
	"ios-safari":    "ios-safari-26",
	"ios-native":    "ios-26-native-apple",
	"native-ios":    "ios-26-native-apple",
	"ios-app":       "ios-26-native-apple",
}

func init() {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		data, err := builtinFS.ReadFile(path.Join("builtin", e.Name()))
		if err != nil {
			panic(err)
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		p, err := Parse(data, name)
		if err != nil {
			panic("builtin profile " + name + ": " + err.Error())
		}
		// Keyed lowercase so lookups are case-insensitive; p.Name keeps its display case.
		builtin[strings.ToLower(p.Name)] = p
	}
}
