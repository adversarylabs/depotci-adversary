//go:build js && wasm

package main

import (
	"io"
	"syscall/js"

	"github.com/rhysd/actionlint"
)

func encodeError(err *actionlint.Error) map[string]interface{} {
	return map[string]interface{}{
		"message": err.Message,
		"line":    err.Line,
		"column":  err.Column,
		"kind":    err.Kind,
	}
}

func runActionlint(_ js.Value, args []js.Value) interface{} {
	source := args[0].String()
	path := args[1].String()
	labels := args[2]
	config := &actionlint.Config{}
	for index := 0; index < labels.Length(); index++ {
		config.SelfHostedRunner.Labels = append(config.SelfHostedRunner.Labels, labels.Index(index).String())
	}
	options := &actionlint.LinterOptions{
		OnRulesCreated: func(rules []actionlint.Rule) []actionlint.Rule {
			for _, rule := range rules {
				rule.SetConfig(config)
			}
			return rules
		},
	}
	linter, err := actionlint.NewLinter(io.Discard, options)
	if err != nil {
		js.Global().Call("__actionlintReject", err.Error())
		return nil
	}
	errs, err := linter.Lint(path, []byte(source), nil)
	if err != nil {
		js.Global().Call("__actionlintReject", err.Error())
		return nil
	}
	ret := make([]interface{}, 0, len(errs))
	for _, err := range errs {
		ret = append(ret, encodeError(err))
	}
	js.Global().Call("__actionlintResolve", js.ValueOf(ret))
	return nil
}

func main() {
	js.Global().Set("__runActionlint", js.FuncOf(runActionlint))
	js.Global().Call("__actionlintReady")
	select {}
}
