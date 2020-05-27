package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

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
			guardarUsuarios()
			os.Mkdir(u.Name, 0777)
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

	case "recuperar": // El cliente recupera un archivo del servidor
		filename := req.Form.Get("user") + "\\" + req.Form.Get("archivo")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Transfer-Encoding", "binary")
		w.Header().Set("Expires", "0")
		data, _ := ioutil.ReadFile(filename)
		fmt.Println(filename)
		http.ServeContent(w, req, filename, time.Now(), bytes.NewReader(data))
		return

	case "directorios":
		usuario := req.Form.Get("user")
		estructura := ""
		files, err := ioutil.ReadDir(usuario)
		if err != nil {
			response(w, false, "El usuario no tiene ningun directorio")
		}
		for _, f := range files {
			estructura += f.Name() + " "
		}
		response(w, true, estructura)

	case "eliminar":
		usuario := req.Form.Get("user")
		archivo := req.Form.Get("filename")
		err := os.Remove(usuario + "\\" + archivo)
		if err != nil {
			response(w, false, "No se ha podido eliminar el archivo")
			return
		}
		response(w, true, "El archivo se ha eliminado correctamente")
	default:
		response(w, false, "Comando inválido")
	}

}

func handleEnviar(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	req.ParseMultipartForm(10 << 21)
	w.Header().Set("Content-Type", "text/plain")
	carpeta := req.Header.Get("usuario")
	filename := req.Header.Get("filename")
	fmt.Println(carpeta + "\\" + filename)

	archivoGuardar, _ := os.OpenFile(carpeta+"\\"+filename, os.O_WRONLY|os.O_CREATE, 0666) // Abrimos un nuevo archivo en la carpeta designada por el cliente
	defer archivoGuardar.Close()

	_, err := io.Copy(archivoGuardar, req.Body)
	if err != nil { // Comprobamos si hay errores en el archivo
		response(w, false, "El archivo no ha llegado correctamente")
		return
	}

	response(w, true, "El archivo ha llegado correctamente")
}

func server() {
	ln, err := net.Listen("tcp", "localhost:1337") // escucha en espera de conexión
	chk(err)
	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	gUsers = make(map[string]user)
	cargarUsuarios()
	http.HandleFunc("/", handler)
	http.HandleFunc("/enviar", handleEnviar)

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

func guardarUsuarios() {
	usuarios, _ := json.MarshalIndent(gUsers, "", "\n")
	ioutil.WriteFile("usuarios.conf", usuarios, 0644)
}

func cargarUsuarios() {
	usuarios, _ := ioutil.ReadFile("usuarios.conf")

	json.Unmarshal(usuarios, &gUsers)
}
