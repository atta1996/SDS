package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/zserge/lorca"
)

// User holds a users account information
/*type Loggeduser struct {
	username string
	logged bool
}*/

var loggeduser string

type counter struct {
	sync.Mutex
	ui lorca.UI
}

type respserv struct {
	Ok  bool   `json:"Ok"`
	Msg string `json:"Msg"`
}

func (c *counter) Redirect(archivo string) {

	c.Lock()
	defer c.Unlock()

	// Load HTML.
	b, err := ioutil.ReadFile("./www/" + archivo + ".html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	c.ui.Load("data:text/html," + url.PathEscape(html))
}

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

func client() {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}
	ui, err := lorca.New("", "", 550, 605, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	// A simple way to know when UI is ready (uses body.onload event in JS)
	ui.Bind("start", func() {
		log.Println("UI is ready")
	})

	// Create and bind Go object to the UI
	c := &counter{}
	c.ui = ui

	ui.Bind("redirect", c.Redirect)

	ui.Bind("getUsername", getLoggedUser)

	//Enlazamos la función login a la UI
	ui.Bind("login", func() {

		//Leemos el email y la contraseña del formulario de login
		user := ui.Eval(`document.getElementById('InputUsername').value`)
		pass := ui.Eval(`document.getElementById('InputPassword').value`)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(pass.String()))
		keyLogin := keyClient[:32] // una mitad para el login (256 bits)

		/*prints de testeo
		log.Println(user)
		log.Println(pass)*/

		data := url.Values{}                 //Declaramos la estructura que contendrá los valores
		data.Set("cmd", "login")             // comando (string)
		data.Set("user", user.String())      // email (string)
		data.Set("pass", encode64(keyLogin)) // contraseña (a base64 porque es []byte)

		r, err := client.PostForm("https://localhost:10443", data) //enviamos la estructura mediante un POST
		chk(err)

		/* prints de testeo
		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		fmt.Println()*/

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta
		defer r.Body.Close()

		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a index.html
			loggeduser = str.Msg //user.String()

			c.Redirect("index")
		}
	})

	//Enlazamos la función login a la UI
	ui.Bind("registro", func() {
		//Leemos el email y la contraseña del formulario de login
		user := ui.Eval(`document.getElementById('registro_usuario').value`)
		email := ui.Eval(`document.getElementById('registro_email').value`)
		pass := ui.Eval(`document.getElementById('registro_password').value`)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(pass.String()))
		keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
		keyData := keyClient[32:64] // la otra para los datos (256 bits)

		// generamos un par de claves (privada, pública) para el servidor
		pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
		chk(err)
		pkClient.Precompute() // aceleramos su uso con un precálculo

		pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
		chk(err)

		keyPub := pkClient.Public()           // extraemos la clave pública por separado
		pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
		chk(err)

		data := url.Values{}                 //Declaramos la estructura que contendrá los valores
		data.Set("cmd", "register")          // comando (string)
		data.Set("user", user.String())      // usuario (string)
		data.Set("email", email.String())    // email (string)
		data.Set("pass", encode64(keyLogin)) // contraseña (a base64 porque es []byte)

		// comprimimos y codificamos la clave pública
		data.Set("pubkey", encode64(compress(pubJSON)))

		// comprimimos, ciframos y codificamos la clave privada
		data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

		r, err := client.PostForm("https://localhost:10443", data) //enviamos la estructura mediante un POST
		chk(err)

		/* prints de testeo
		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		fmt.Println()*/

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta
		defer r.Body.Close()

		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a login.html
			c.Redirect("login")
		}
	})

	ui.Bind("enviar", func() {

		//Leemos el email y la contraseña del formulario de login
		rutaarchivo := ui.Eval(`document.getElementById('filePath').value`)

		dir := filepath.Base(rutaarchivo.String())

		ficherozip := loggeduser + "-" + dir + "-" + time.Now().Format("2006-1-02-15-04-05") + ".zip"

		outFile, err := os.Create(ficherozip)

		if err != nil {
			fmt.Println(err)
		}

		// Create a new zip archive.
		w := zip.NewWriter(outFile)
		defer w.Close()

		// Add some files to the archive.
		addFiles(w, rutaarchivo.String(), "")

		if err != nil {
			fmt.Println(err)
		}

		// Make sure to check the error on Close.
		err = w.Close()
		if err != nil {
			fmt.Println(err)
		}

		f, _ := os.Open(ficherozip)
		req, err := http.NewRequest("POST", "https://localhost:10443/enviar", f)
		req.Header.Add("usuario", loggeduser)
		req.Header.Add("filename", ficherozip)
		chk(err)

		client := &http.Client{}
		r, err := client.Do(req)
		chk(err)

		outFile.Close()
		os.Remove(ficherozip)

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta
		defer r.Body.Close()

		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		fmt.Println()
		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a index.html
			c.Redirect("index")
		}

	})

	// Load HTML.
	b, err := ioutil.ReadFile("./www/login.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

	// You may use console.log to debug your JS code, it will be printed via
	// log.Println(). Also exceptions are printed in a similar manner.
	ui.Eval(`
		console.log("Hello, world!");
		console.log('Multiple values:', [1, false, {"x":5}]);
	`)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

}

func getLoggedUser() string {
	if loggeduser != "" {
		return loggeduser
	}
	return "ERROR"
}

func addFiles(w *zip.Writer, rutaarchivo, baseInZip string) {
	// Open the Directory

	files, err := ioutil.ReadDir(rutaarchivo)
	if err != nil {

		dat, err := ioutil.ReadFile(rutaarchivo)

		_, dor := filepath.Split(rutaarchivo)
		f, err := w.Create(baseInZip + dor)

		if err != nil {
			fmt.Println(err)
		}
		_, err = f.Write(dat)
		if err != nil {
			fmt.Println(err)
		}
	}

	for _, file := range files {
		fmt.Println(rutaarchivo + file.Name())
		if !file.IsDir() {
			dat, err := ioutil.ReadFile(rutaarchivo + file.Name())
			if err != nil {
				fmt.Println(err)
			}

			// Add some files to the archive.
			f, err := w.Create(baseInZip + file.Name())
			if err != nil {
				fmt.Println(err)
			}
			_, err = f.Write(dat)
			if err != nil {
				fmt.Println(err)
			}
		} else if file.IsDir() {

			// Recurse
			newBase := rutaarchivo + file.Name() + "/"
			//log.Println("Recursing and Adding SubDir: " + file.Name())
			//log.Println("Recursing and Adding SubDir: " + newBase)

			addFiles(w, newBase, baseInZip+file.Name()+"/")
		}
	}
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
