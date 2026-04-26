package main

import "encoding/json"

func marshalState(state AppState) ([]byte, error) {
	return json.MarshalIndent(state, "", "  ")
}

func unmarshalState(data []byte, state *AppState) error {
	return json.Unmarshal(data, state)
}
