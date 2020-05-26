package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
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

func client() {

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
		log.Println(email)
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

		/*prints de testeo
		log.Println(filepath)
		log.Println(filepath.String())*/

		//_, dor := filepath.Split(rutaarchivo.String())
		dir := filepath.Base(rutaarchivo.String())

		ficherozip := loggeduser + "-" + dir + "-" + time.Now().Format("2006-1-02-15-04-05") + ".zip"

		outFile, err := os.Create(ficherozip)

		if err != nil {
			fmt.Println(err)
		}
		//defer outFile.Close()

		// Create a new zip archive.
		w := zip.NewWriter(outFile)

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

		r, err := http.NewRequest("POST", "https://localhost:10443/enviar", outFile)
		chk(err)

		outFile.Close()
		os.Remove(ficherozip)

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta
		defer r.Body.Close()

		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a index.html
			c.Redirect("index")
		}

		/*resp, err := client.Do(r)
		if err != nil {
			log.Fatal(err)
		}
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}*/

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
			log.Println("Recursing and Adding SubDir: " + file.Name())
			log.Println("Recursing and Adding SubDir: " + newBase)

			addFiles(w, newBase, baseInZip+file.Name()+"/")
		}
	}
}
