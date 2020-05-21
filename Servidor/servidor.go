package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
)

type UsuPass struct {
	User     string
	Password string
}

const archivoPass = "passwords.json"

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

			opcion := scanner.Text() //Leemos la opcion que quiere utilizar el usuario
			switch opcion {
			case "e": //Para recibir archivos
				recibirArchivo(scanner)
			case "r": //Para enviar archivos
				recuperarArchivo(scanner)
			case "d":
				directorios(scanner)
			case "l":
				login(scanner)
			case "reg":
				registro(scanner)
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

//A traves del scanner se recibe el usuario, la ruta y el nombre del archivo y el archivo
func recibirArchivo(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()
	scanner.Scan()
	rutaYArchivo := scanner.Text()

	fichero, _ := os.Open("/" + usuario + "/" + rutaYArchivo)

	for scanner.Scan() { //Escribir la entrada de scanner en el fichero
		fmt.Print(fichero, "%s", scanner.Text())
	}
	defer fichero.Close()

}

//A traves del scanner recibe el usuario, la ruta y el nombre del archivo y se transmite el archivo
func recuperarArchivo(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()
	scanner.Scan()
	rutaYArchivo := scanner.Text()
	fichero, _ := os.Open("/" + usuario + "/" + rutaYArchivo)

	fmt.Print(scanner, "%s", fichero)

	defer fichero.Close()
}

//Para utilizar con versiones de archivos
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

//Directorios
func directorios(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()

	estructura := usuario
	err := filepath.Walk(estructura,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			estructura += path
			return nil
		})
	if err != nil {
		log.Println(err)
	}
	fmt.Print(scanner, "%s", estructura)
}

//Login
func login(scanner *bufio.Scanner) {
	/*	scanner.Scan()
		usuario := scanner.Text()
		scanner.Scan()
		pass := scanner.Text()
		//Buscar la entrada en la base de datos
	*/
}

//Registro
func registro(scanner *bufio.Scanner) {
	scanner.Scan()
	usuario := scanner.Text()
	scanner.Scan()
	pass := scanner.Text()
	//Añadir la entrada en la base de datos

	aGuardar := UsuPass{
		User:     usuario,
		Password: pass,
	}

	guardado, _ := json.MarshalIndent(aGuardar, "", "")
	ioutil.WriteFile(archivoPass, guardado, 0644)
}

func registroPrueba(usuario string, pass string) {
	//Añadir la entrada en la base de datos

	aGuardar := UsuPass{
		User:     usuario,
		Password: pass,
	}

	fichero, _ := os.Open(archivoPass)
	byteValue, _ := ioutil.ReadAll(fichero)

	guardado, _ := json.MarshalIndent(aGuardar, "", " ")

	guardado2 := append(byteValue, guardado...)

	json.Unmarshal(byteValue, &guardado2)

	_ = ioutil.WriteFile(archivoPass, guardado2, 0644)
}
