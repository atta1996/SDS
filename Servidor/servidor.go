package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

type UsuPass struct {
	User     string
	Password string
}

type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

type user struct {
	Name  string            // nombre de usuario
	Hash  []byte            // hash de la contraseña
	Salt  []byte            // sal para la contraseña
	Data  map[string]string // datos adicionales del usuario
	Email string            //email del usuario
}

var gUsers map[string]user

const archivoPass = "passwords.json"

func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func responseFile(w http.ResponseWriter, file *os.File, filename string) {
	FileHeader := make([]byte, 512)
	file.Read(FileHeader)

	FileContentType := http.DetectContentType(FileHeader)
	FileStat, _ := file.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", FileSize)

	file.Seek(0, 0)
	io.Copy(w, file)
	return
}

func responseFileComprimido(w http.ResponseWriter, file *os.File, filename string) {
	FileHeader := make([]byte, 512)
	file.Read(FileHeader)

	stream := cifradorAES256()
	var dec cipher.StreamReader
	dec.S = stream
	dec.R = file

	rd, err := zlib.NewReader(dec)
	if err != nil { // Comprobamos si hay errores en el archivo
		response(w, false, "Ha habido un error leyendo el archivo")
		return
	}

	FileContentType := http.DetectContentType(FileHeader)
	FileStat, _ := file.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", FileSize)

	file.Seek(0, 0)
	io.Copy(w, rd)
	return
}

func cifradorAES256() cipher.Stream {
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte("SDS2020"))
	chk(err)
	key := h.Sum(nil)

	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	chk(err)
	iv := h.Sum(nil)

	block, err := aes.NewCipher(key)
	chk(err)
	S := cipher.NewCTR(block, iv[:16])

	return S
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm() // es necesario parsear el formulario

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		w.Header().Set("Content-Type", "text/plain")
		u := user{}
		u.Name = req.Form.Get("user")              // nombre
		u.Salt = make([]byte, 16)                  // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                          // la sal es aleatoria
		u.Data = make(map[string]string)           // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey") // clave privada
		u.Data["public"] = req.Form.Get("pubkey")  // clave pública
		password := decode64(req.Form.Get("pass")) // contraseña (keyLogin)
		u.Email = req.Form.Get("email")

		// "hasheamos" la contraseña con scrypt
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		_, ok := gUsers[u.Name] // ¿existe ya el usuario?
		ok2 := false
		for _, buscaEmail := range gUsers {
			if buscaEmail.Email == u.Email {
				ok2 = true
			}
		}
		if ok || ok2 {
			response(w, false, "Usuario ya registrado")
		} else {
			gUsers[u.Name] = u
			response(w, true, "Usuario registrado")
		}

	case "login": // ** login
		w.Header().Set("Content-Type", "text/plain")
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		ok2 := false
		for _, buscaEmail := range gUsers {
			if buscaEmail.Email == req.Form.Get("email") {
				ok2 = true
				u = buscaEmail
			}
		}
		if !ok && !ok2 {
			response(w, false, "Usuario inexistente")
			return
		}

		password := decode64(req.Form.Get("pass"))               // obtenemos la contraseña
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)
		if bytes.Compare(u.Hash, hash) != 0 {                    // comparamos
			response(w, false, "Credenciales inválidas")
			return
		}
		response(w, true, u.Name)

	case "enviar": // El cliente envia un archivo
		w.Header().Set("Content-Type", "text/plain")
		usuario := req.Form.Get("user")
		carpeta := req.Form.Get("carpeta")               // Se necesita la carpeta para almacenar archivos
		file, fileheader, err := req.FormFile("archivo") // Leemos el archivo que nos envian
		if err != nil {                                  // Comprobamos si hay errores en el archivo
			response(w, false, "El archivo no ha llegado correctamente")
			return
		}
		defer file.Close()

		archivoGuardar, _ := os.Create("/" + usuario + "/" + carpeta + "/" + fileheader.Filename) // Abrimos un nuevo archivo en la carpeta designada por el cliente

		stream := cifradorAES256() // Creamos el streamWriter
		var enc cipher.StreamWriter
		enc.S = stream
		enc.W = archivoGuardar
		defer archivoGuardar.Close()

		wr := zlib.NewWriter(enc) // Comprimimos

		_, err = io.Copy(wr, file)
		if err != nil { // Comprobamos si hay errores en el archivo
			response(w, false, "El archivo no ha llegado correctamente")
			return
		}

		response(w, true, "El archivo ha llegado correctamente")

	case "recuperar": // El cliente recupera un archivo del servidor
		filename := "/" + req.Form.Get("user") + "/" + req.Form.Get("carpeta") + "/" + req.Form.Get("archivo")
		archivoEnviar, err := os.Open(filename)
		if err != nil {
			response(w, false, "El archivo no existe o no esta en esta carpeta")
			return
		}
		defer archivoEnviar.Close()
		responseFileComprimido(w, archivoEnviar, filename)

	case "directorios":
		usuario := req.Form.Get("user")
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
			response(w, false, "El usuario no tiene ningun directorio")
		}
		response(w, true, estructura)

	default:
		response(w, false, "Comando inválido")
	}

}

func server() {
	ln, err := net.Listen("tcp", "localhost:1337") // escucha en espera de conexión
	chk(err)
	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	gUsers = make(map[string]user)
	http.HandleFunc("/", handler)

	chk(http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil))
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

//Para utilizar con versiones de archivos
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

//Directorios
func directorios(scanner *bufio.Scanner) { //Pendiente de implementar en el handler
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

/*func registroPrueba(usuario string, pass string) {
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
*/
