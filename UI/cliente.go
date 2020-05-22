package main

import (
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
	"runtime"
	"sync"

	"github.com/zserge/lorca"
)

type counter struct {
	sync.Mutex
	count int
	ui    lorca.UI
}

type respserv struct {
	Ok  bool `json:"Ok"`
	Msg bool `json:"Msg"`
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

	//Enlazamos la función login a la UI
	ui.Bind("login", func() {
		//Leemos el email y la contraseña del formulario de login
		email := ui.Eval(`document.getElementById('InputEmail').value`)
		pass := ui.Eval(`document.getElementById('InputPassword').value`)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(pass.String()))
		keyLogin := keyClient[:32] // una mitad para el login (256 bits)
		//keyData := keyClient[32:64] // la otra para los datos (256 bits)

		/*prints de testeo
		log.Println(email)
		log.Println(pass)*/

		data := url.Values{}                 //Declaramos la estructura que contendrá los valores
		data.Set("cmd", "l")                 // comando (string)
		data.Set("email", email.String())    // email (string)
		data.Set("pass", encode64(keyLogin)) // contraseña (a base64 porque es []byte)

		r, err := client.PostForm("https://localhost:10443", data) //enviamos la estructura mediante un POST
		chk(err)

		/* prints de testeo
		io.Copy(os.Stdout, r.Body) 			 // mostramos el cuerpo de la respuesta (es un reader)
		fmt.Println()*/

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta

		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a index.html
			c.Redirect("index")
		}
	})

	//Enlazamos la función login a la UI
	ui.Bind("singin", func() {
		//Leemos el email y la contraseña del formulario de login
		user := ui.Eval(`document.getElementById('registro_usuario').value`)
		email := ui.Eval(`document.getElementById('registro_email').value`)
		pass := ui.Eval(`document.getElementById('registro_password').value`)

		// hash con SHA512 de la contraseña
		keyClient := sha512.Sum512([]byte(pass.String()))
		keyLogin := keyClient[:32] // una mitad para el login (256 bits)
		//keyData := keyClient[32:64] // la otra para los datos (256 bits)

		log.Println(user)
		log.Println(email)
		log.Println(pass)

		data := url.Values{}                 //Declaramos la estructura que contendrá los valores
		data.Set("cmd", "reg")               // comando (string)
		data.Set("user", user.String())      // usuario (string)
		data.Set("email", email.String())    // email (string)
		data.Set("pass", encode64(keyLogin)) // contraseña (a base64 porque es []byte)

		r, err := client.PostForm("https://localhost:10443", data) //enviamos la estructura mediante un POST
		chk(err)

		/* prints de testeo
		io.Copy(os.Stdout, r.Body) 			 // mostramos el cuerpo de la respuesta (es un reader)
		fmt.Println()*/

		var body []byte
		body, err = ioutil.ReadAll(r.Body) //Leemos el contenido de la respuesta

		var str respserv
		_ = json.Unmarshal(body, &str) //Asignamos el contenido de la respuesta a la variable str

		if str.Ok { // Si el usuario y contraseña son correctos redirigimos a login.html
			c.Redirect("login")
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

	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	/*tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
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

	// ** ejemplo de registro
	data := url.Values{}                 // estructura para contener los valores
	data.Set("cmd", "register")          // comando (string)
	data.Set("user", "usuario")          // usuario (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", encode64(compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()

	// ** ejemplo de login
	data = url.Values{}
	data.Set("cmd", "login")             // comando (string)
	data.Set("user", "usuario")          // usuario (string)
	data.Set("pass", encode64(keyLogin)) // contraseña (a base64 porque es []byte)
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	fmt.Println()*/
}

//test
