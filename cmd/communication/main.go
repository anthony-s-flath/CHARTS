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

	fmt.Printf(
		"CHARTS communication sizes\n"+
			"n=%d b=%d L=%d N=%d\n\n",
		n,
		b,
		n/b,
		params.N(),
	)

	senders, keys, err := charts.NewSenders(
		params,
		n,
		b,
		[]byte("charts-communication"),
	)
	must(err)

	requests := make([]charts.Request, n)

	for sender := range senders {
		requests[sender], err = senders[sender].EncryptWithTag(
			uint64(sender+1),
			demoMessage(params.N(), sender),
		)
		must(err)
	}

	// ------------------------------------------------------------
	// Sender -> Router
	// ------------------------------------------------------------

	request := requests[0]

	headerBytes := request.Header.BinarySize()

	controlBytes := 0
	if request.Control != nil {
		controlBytes = request.Control.BinarySize()
	}

	payloadCiphertextBytes := request.Payloads[0].BinarySize()

	payloadBytes := 0
	for _, payload := range request.Payloads {
		payloadBytes += payload.BinarySize()
	}

	requestBytes := headerBytes + controlBytes + payloadBytes

	fmt.Println("Sender -> Router")
	printSize("Header ciphertext", headerBytes)

	if request.Control != nil {
		printSize("Control ciphertext", controlBytes)
	}

	printSize("One payload ciphertext", payloadCiphertextBytes)
	printSize("All payload ciphertexts", payloadBytes)
	printSize("One complete request", requestBytes)
	printSize("All sender requests", n*requestBytes)

	fmt.Println()

	// ------------------------------------------------------------
	// Router output
	// ------------------------------------------------------------

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

	outputHeaderBytes := output.Header.BinarySize()
	outputPayloadCiphertextBytes := output.Payloads[0].BinarySize()

	outputPayloadBytes := 0
	for _, payload := range output.Payloads {
		outputPayloadBytes += payload.BinarySize()
	}

	outputBytes := outputHeaderBytes + outputPayloadBytes

	fmt.Println("Router Output")
	printSize("Header ciphertext", outputHeaderBytes)
	printSize("One payload ciphertext", outputPayloadCiphertextBytes)
	printSize("All payload ciphertexts", outputPayloadBytes)
	printSize("Complete router output", outputBytes)

	fmt.Println()

	// ------------------------------------------------------------
	// Partial Decryption -> Router
	// ------------------------------------------------------------

	partials := make([]charts.PartialDecryption, n)

	for sender := range senders {
		partials[sender], err = senders[sender].PartialDecrypt(
			output,
			cfg.Noise,
		)
		must(err)
	}

	partial := partials[0]

	partialHeaderBytes := partial.Header.BinarySize()
	partialPayloadShareBytes := partial.Payloads[0].BinarySize()

	partialPayloadBytes := 0
	for _, share := range partial.Payloads {
		partialPayloadBytes += share.BinarySize()
	}

	partialBytes := partialHeaderBytes + partialPayloadBytes

	fmt.Println("Partial Decryption -> Router")
	printSize("Header share", partialHeaderBytes)
	printSize("One payload share", partialPayloadShareBytes)
	printSize("All payload shares", partialPayloadBytes)
	printSize("One user's partial decryption", partialBytes)
	printSize("All users' partial decryptions", n*partialBytes)

	fmt.Println()

	// ------------------------------------------------------------
	// Totals
	// ------------------------------------------------------------

	senderRoundBytes := n * requestBytes
	decryptionRoundBytes := n * partialBytes

	fmt.Println("Communication Totals")
	printSize("All sender uploads", senderRoundBytes)
	printSize("All partial-decryption uploads", decryptionRoundBytes)
	printSize(
		"Total client -> router communication",
		senderRoundBytes+decryptionRoundBytes,
	)
}

func printSize(label string, bytes int) {
	fmt.Printf(
		"  %-36s %12d bytes  %10.2f KiB  %8.3f MiB\n",
		label,
		bytes,
		float64(bytes)/1024,
		float64(bytes)/(1024*1024),
	)
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
