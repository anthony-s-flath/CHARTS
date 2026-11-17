package main

import (
	"fmt"

	charts "github.com/anthony-s-flath/CHARTS/charts"
	"github.com/anthony-s-flath/CHARTS/internal/config"
)

func main() {
	cfg, err := config.Load()
	must(err)
	fmt.Println(cfg.String())
	params, n, b := cfg.Params, cfg.N, cfg.B

	inputs := make([]charts.Message, n)
	for i := range inputs {
		inputs[i] = charts.Message{Tag: uint64(i + 2), Coefficients: demoMessage(params.N(), i)}
	}

	senders, keys, err := charts.NewSenders(
		params,
		n,
		b,
		[]byte("charts-demo"),
	)
	must(err)

	requests := make([]charts.Request, n)
	for sender, input := range inputs {
		requests[sender], err = senders[sender].EncryptWithTag(
			input.Tag,
			input.Coefficients,
		)
		must(err)
	}

	router, err := charts.NewRouter(
		params,
		n,
		b,
		keys.RelinKey,
		keys.GaloisKeys,
	)
	must(err)
	must(router.Route(requests))

	output := router.Output()
	partials := make([]charts.PartialDecryption, len(senders))
	for sender := range senders {
		partials[sender], err = senders[sender].PartialDecrypt(
			output,
			cfg.Noise,
		)
		must(err)
	}
	opened, err := router.AggregatePartialDecryptions(
		output,
		partials,
		cfg.Noise,
	)
	must(err)

	recovered, err := charts.Decode(opened, params)
	must(err)

	fmt.Printf(
		"n=%d b=%d L=%d N=%d\n",
		n,
		b,
		n/b,
		params.N(),
	)
	for _, message := range recovered {
		fmt.Printf(
			"tag=%d coefficients=%d prefix=%v\n",
			message.Tag,
			len(message.Coefficients),
			message.Coefficients[:8],
		)
	}
}

func demoMessage(length int, sender int) []uint64 {
	message := make([]uint64, length)
	for coefficient := range message {
		message[coefficient] = uint64(
			(sender + 1) * (coefficient + 1),
		)
	}
	return message
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
