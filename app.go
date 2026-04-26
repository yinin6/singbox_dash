package main

const (
	addr      = "127.0.0.1:8088"
	stateDir  = "data"
	stateFile = "data/state.json"
)

var store = &Store{}

func main() {
	if err := store.load(); err != nil {
		panic(err)
	}

	mux := newMux()
	if err := serve(addr, mux); err != nil {
		panic(err)
	}
}
