package server

import (
	"fmt"
	"log"
	"net/http"
)

// Start a simple fileserver to export the model.
func Start(port int, dir string) {
	http.Handle("/", http.FileServer(http.Dir(dir)))

	log.Printf("Serving on: 127.0.0.1:%d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), nil))
	return
}
