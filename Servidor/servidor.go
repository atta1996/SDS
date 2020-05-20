package Servidor

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func server() {
	ln, err := net.Listen("tcp", "localhost:1337") // escucha en espera de conexión
	chk(err)
	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	for { // búcle infinito, se sale con ctrl+c
		conn, err := ln.Accept() // para cada nueva petición de conexión
		chk(err)
		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			chk(err)

			fmt.Println("conexión: ", conn.LocalAddr(), " <--> ", conn.RemoteAddr())

			scanner := bufio.NewScanner(conn) // el scanner nos permite trabajar con la entrada línea a línea (por defecto)

			scanner.Scan()
			opcion := scanner.Text()
			switch opcion {
			case "e":
				recibirArchivo(scanner)
			case "r":
				recuperarArchivo(scanner)
			}

			conn.Close() // cerramos al finalizar el cliente (EOF se envía con ctrl+d o ctrl+z según el sistema)
			fmt.Println("cierre[", port, "]")
		}()
	}
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	fmt.Println("Abriendo servidor en puerto 1337")
	server()
}

func recibirArchivo(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()
	scanner.Scan()
	rutaYArchivo := scanner.Text()

	fichero, _ := os.Open(usuario + "/" + rutaYArchivo)

	for scanner.Scan() { //Escribir la entrada de scanner en el fichero
		fmt.Print(fichero, "%s", scanner.Text())
	}
	defer fichero.Close()

}

func recuperarArchivo(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()
	scanner.Scan()
	rutaYArchivo := scanner.Text()

	fichero, _ := os.Open(usuario + "/" + rutaYArchivo)

	for scanner.Scan() { //Escribir en el scanner el fichero
		fmt.Print(scanner.Text(), "%s", fichero)
	}
	defer fichero.Close()
}
