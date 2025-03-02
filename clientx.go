package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
)

type SystemSetup struct {
	q     *big.Int
	P     *big.Int
	curve elliptic.Curve
	cp    *elliptic.CurveParams
	s     *big.Int
	P_pub *big.Int
}

type Collosopn_Resistant_Hash struct {
	Hash1 *big.Int
	Hash2 *big.Int
	Hash3 *big.Int
	Hash4 *big.Int
}

type PPK_1 struct {
	d *big.Int
	R *big.Int
}

type PPK_2 struct {
	d *big.Int
	R *big.Int
}
type PublicKey_1 struct {
	Q *big.Int
	R *big.Int
}

type SecretKey_1 struct {
	d *big.Int
	x *big.Int
}

type PublicKey_2 struct {
	Q *big.Int
	R *big.Int
}

type SecretKey_2 struct {
	d *big.Int
	x *big.Int
}

type Signcryption struct {
	M  string
	T  string
	c1 []byte
	c2 *big.Int
	U  *big.Int
	v  *big.Int
}

const (
	Sendertitle   = "Sender"
	ReceiverTitle = "Receiver"
)

//go:embed R-C.png
var png []byte

func main() {
	myApp := app.New()
	sendWindow := myApp.NewWindow(Sendertitle)
	receiveWindow := myApp.NewWindow(ReceiverTitle)

	sendWindow.SetContent(sendContent(sendWindow, receiveWindow))
	sendWindow.Resize(fyne.NewSize(1000, 600))
	sendWindow.CenterOnScreen()
	sendWindow.Show()
	//server_init()
	sys := setup_client()
	_, _ = sys.PPKGenerationUser2()
	_, _ = sys.PPKGenerationUser1()
	myApp.Run()

}

func sendContent(sendWindow, receiveWindow fyne.Window) fyne.CanvasObject {
	send_addressLabel := widget.NewLabel("address and port input")
	send_addressEditor := widget.NewMultiLineEntry()
	send_addressEditor.SetPlaceHolder("address")
	send_addressEditor.SetMinRowsVisible(1)

	send_port1 := widget.NewMultiLineEntry()
	send_port1.SetPlaceHolder("port")
	send_port1.SetMinRowsVisible(1)
	send_port1.TextStyle.Monospace = true

	send_ppk := widget.NewMultiLineEntry()
	send_ppk.SetPlaceHolder("ppk")
	send_ppk.SetMinRowsVisible(1)
	send_ppk.TextStyle.Monospace = true
	U1H := new(Collosopn_Resistant_Hash)
	ppk1 := new(PPK_1)
	sys := setup_client()
	verifyBtn := widget.NewButton("Verify", func() {
		ppkBase64 := send_ppk.Text
		ppkBytes, err := base64.StdEncoding.DecodeString(ppkBase64)
		if err != nil {
			log.Println("Failed to decode base64:", err)
			return
		}
		if len(ppkBytes) != 129 {
			log.Println("Invalid ppk length")
			return
		}
		ppk1 = &PPK_1{
			R: new(big.Int).SetBytes(ppkBytes[:65]),
			d: new(big.Int).SetBytes(ppkBytes[65:]),
		}

		H1str := "user1" + ppk1.R.String() + sys.P_pub.String()
		U1H.Hash1 = HashNormal(H1str)
		left := sys.PointMul(ppk1.d, sys.P)
		right := sys.PointMul(U1H.Hash1, sys.P_pub)
		right = sys.PointAdd(right, ppk1.R)
		fmt.Println(left.Cmp(right))

	})

	add_info := widget.NewLabel("Choose target document")

	var selectedFilePath string

	send_port1_add := container.NewVBox(
		send_port1,
		container.NewVBox(send_ppk, verifyBtn),
		container.NewHBox(
			add_info,
			layout.NewSpacer(),
			widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
				dialog.ShowFileOpen(func(file fyne.URIReadCloser, err error) {
					if err != nil {
						dialog.ShowError(err, sendWindow)
						return
					}
					if file == nil {
						log.Println("Cancelled")
						return
					}
					selectedFilePath = file.URI().Path()
					log.Println("Selected file:", selectedFilePath)
				}, sendWindow)
			}),
		),
	)

	left_container := container.New(layout.NewVBoxLayout(), send_addressLabel, send_addressEditor)
	right_container := container.New(layout.NewVBoxLayout(), send_port1_add)
	grid := container.New(layout.NewGridLayoutWithRows(2), left_container, right_container)

	app_title := canvas.NewText(Sendertitle, color.NRGBA{0, 0x80, 0, 0xff})
	app_title.TextSize = 24

	//current_folder, _ := os.Getwd()

	background := canvas.NewImageFromResource(fyne.NewStaticResource("pic.png", png))
	background.SetMinSize(fyne.NewSize(50, 50))

	modeBtn := widget.NewButtonWithIcon("Mode", theme.StorageIcon(), func() {
		receiveWindow.SetContent(receiveContent(sendWindow, receiveWindow))
		receiveWindow.Resize(fyne.NewSize(1000, 600))
		receiveWindow.CenterOnScreen()
		receiveWindow.Show()
		sendWindow.Hide()
	})
	modeBtn.Importance = widget.HighImportance
	var send_port string

	optionBtn := widget.NewButtonWithIcon("Option", theme.SettingsIcon(), func() {
		showOptionWindow(sendWindow, &send_port)
	})
	optionBtn.Importance = widget.DangerImportance

	aboutBtn := widget.NewButtonWithIcon("Help", theme.QuestionIcon(), func() {})
	aboutBtn.Importance = widget.LowImportance

	status_container := container.New(layout.NewHBoxLayout(), layout.NewSpacer(), modeBtn, optionBtn, aboutBtn)

	sendBtn := widget.NewButtonWithIcon("Send", theme.MailSendIcon(), func() {
		client1(selectedFilePath, send_addressEditor.Text, send_port1.Text, send_port, U1H, ppk1)
	})
	sendBtn.Importance = widget.SuccessImportance

	return container.New(layout.NewGridLayoutWithColumns(2),
		background,
		container.New(layout.NewVBoxLayout(), app_title, status_container, grid, sendBtn),
	)
}

func receiveContent(sendWindow, receiveWindow fyne.Window) fyne.CanvasObject {
	recv_addressLabel := widget.NewLabel("address and port input")
	recv_addressEditor := widget.NewMultiLineEntry()
	recv_addressEditor.SetPlaceHolder("address")
	recv_addressEditor.SetMinRowsVisible(1)

	recv_port1 := widget.NewMultiLineEntry()
	recv_port1.SetPlaceHolder("port")
	recv_port1.SetMinRowsVisible(1)
	recv_port1.TextStyle.Monospace = true

	recv_ppk := widget.NewMultiLineEntry()
	recv_ppk.SetPlaceHolder("ppk")
	recv_ppk.SetMinRowsVisible(1)
	recv_ppk.TextStyle.Monospace = true
	U2H := new(Collosopn_Resistant_Hash)
	ppk2 := new(PPK_2)
	verifyBtn := widget.NewButton("Verify", func() {
		ppkBase64 := recv_ppk.Text
		ppkBytes, err := base64.StdEncoding.DecodeString(ppkBase64)
		if err != nil {
			log.Println("Failed to decode base64:", err)
			return
		}
		if len(ppkBytes) != 129 {
			log.Println("Invalid ppk length")
			return
		}
		ppk2 = &PPK_2{
			R: new(big.Int).SetBytes(ppkBytes[:65]),
			d: new(big.Int).SetBytes(ppkBytes[65:]),
		}
		sys := setup_client()

		H1str := "user2" + ppk2.R.String() + sys.P_pub.String()
		U2H.Hash1 = HashNormal(H1str)
		left := sys.PointMul(ppk2.d, sys.P)
		right := sys.PointMul(U2H.Hash1, sys.P_pub)
		right = sys.PointAdd(right, ppk2.R)
		fmt.Println(left.Cmp(right))
	})

	add_info := widget.NewLabel("Choose target directory")

	var selectedDirPath string

	recv_port1_add := container.NewVBox(
		recv_port1,
		container.NewVBox(recv_ppk, verifyBtn),
		container.NewHBox(
			add_info,
			layout.NewSpacer(),
			widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
				dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
					if err != nil {
						dialog.ShowError(err, receiveWindow)
						return
					}
					if uri == nil {
						log.Println("Cancelled")
						return
					}
					selectedDirPath = uri.Path()
					log.Println("Selected directory:", selectedDirPath)
				}, receiveWindow)
			}),
		),
	)

	left_container := container.New(layout.NewVBoxLayout(), recv_addressLabel, recv_addressEditor)
	right_container := container.New(layout.NewVBoxLayout(), recv_port1_add)
	grid := container.New(layout.NewGridLayoutWithRows(2), left_container, right_container)

	app_title := canvas.NewText(ReceiverTitle, color.NRGBA{0, 0x80, 0, 0xff})
	app_title.TextSize = 24
	//current_folder, _ := os.Getwd()

	background := canvas.NewImageFromResource(fyne.NewStaticResource("pic.png", png))
	background.SetMinSize(fyne.NewSize(50, 50))

	modeBtn := widget.NewButtonWithIcon("Mode", theme.StorageIcon(), func() {
		sendWindow.SetContent(sendContent(sendWindow, receiveWindow))
		sendWindow.Resize(fyne.NewSize(1000, 600))
		sendWindow.CenterOnScreen()
		sendWindow.Show()
		receiveWindow.Hide()
	})
	modeBtn.Importance = widget.HighImportance

	var recv_port string

	optionBtn := widget.NewButtonWithIcon("Option", theme.SettingsIcon(), func() {
		showOptionWindow(receiveWindow, &recv_port)
	})
	optionBtn.Importance = widget.DangerImportance

	aboutBtn := widget.NewButtonWithIcon("Help", theme.QuestionIcon(), func() {})
	aboutBtn.Importance = widget.LowImportance

	status_container := container.New(layout.NewHBoxLayout(), layout.NewSpacer(), modeBtn, optionBtn, aboutBtn)

	startBtn := widget.NewButtonWithIcon("Listen", theme.MediaPlayIcon(), func() {
		client2(selectedDirPath, recv_addressEditor.Text, recv_port1.Text, U2H, recv_port)
	})
	startBtn.Importance = widget.WarningImportance

	return container.New(layout.NewVBoxLayout(),
		container.New(layout.NewHBoxLayout(), background, app_title),
		status_container,
		grid,
		startBtn,
	)
}

func showOptionWindow(parent fyne.Window, p *string) {
	optionWindow := fyne.CurrentApp().NewWindow("Option")
	optionWindow.Resize(fyne.NewSize(300, 200))
	optionWindow.CenterOnScreen()

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Enter port")
	port := ""
	checkBtn := widget.NewButton("Check", func() {
		port = portEntry.Text
		if isPortAvailable(port) {
			dialog.ShowInformation("Success", "Port is available", optionWindow)
		} else {
			dialog.ShowError(fmt.Errorf("Port is not available"), optionWindow)
		}
		*p = port
	})

	content := container.NewVBox(
		widget.NewLabel("Enter port number:"),
		portEntry,
		checkBtn,
	)

	optionWindow.SetContent(content)
	optionWindow.Show()
	//log.Println("Port:", port)
}

func isPortAvailable(port string) bool {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func client1(selectedFilePath string, receiver_IP string, receiver_port string, send_port string, U1H *Collosopn_Resistant_Hash, ppk1 *PPK_1) {
	pk_1, _, SigC := c_init()
	sys := setup_client()

	var params []string

	conn1 := startReceiver(send_port)
	if conn1 != nil {
		params = receiveMessage(conn1)
		conn1.Close()
		if len(params) < 6 {
			log.Println("Received invalid parameters")
			return
		}
	}
	U2_H_Hash1, _ := new(big.Int).SetString(params[0], 10)
	U2_H_Hash2, _ := new(big.Int).SetString(params[1], 10)
	U2_H_Hash3, _ := new(big.Int).SetString(params[2], 10)
	U2_H_Hash4, _ := new(big.Int).SetString(params[3], 10)
	pk_2_q, _ := new(big.Int).SetString(params[4], 10)
	pk_2_R, _ := new(big.Int).SetString(params[5], 10)
	pk_2 := &PublicKey_2{
		Q: pk_2_q,
		R: pk_2_R,
	}
	U2H := &Collosopn_Resistant_Hash{
		Hash1: U2_H_Hash1,
		Hash2: U2_H_Hash2,
		Hash3: U2_H_Hash3,
		Hash4: U2_H_Hash4,
	}
	//从客户端2接收到的参数

	file_content, _ := processFile(selectedFilePath)
	send_c(file_content, U1H, U2H, sys, pk_2, ppk1)

	message := joinParams(pk_1.Q.String(), pk_1.R.String(), string(SigC.c1), SigC.c2.String(), SigC.U.String(), SigC.v.String(), U1H.Hash1.String(), U1H.Hash2.String(), U1H.Hash3.String(), U1H.Hash4.String())
	conn1 = createConnection(receiver_IP, receiver_port)
	if conn1 != nil {
		sendMessage(conn1, message)
		conn1.Close()
	}
	//发送给客户端的参数

}
func sendMessage(conn net.Conn, message string) {
	_, err := conn.Write([]byte(message))
	if err != nil {
		log.Println("Write error:", err)
		return
	}
	log.Println("Message sent:", message)
}

func createConnection(ip, port string) net.Conn {
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		log.Println("Connection error:", err)
		return nil
	}
	return conn
}
func joinParams(params ...string) string {
	return strings.Join(params, ",")
}

func processFile(filePath string) ([]byte, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Println("File open error:", err)
		return nil, err
	}
	defer file.Close()

	// Send the file name
	//fileName := file.Name()
	//_, err = conn.Write([]byte(fileName + "\n"))
	if err != nil {
		fmt.Println("File name send error:", err)
		return nil, err
	}

	// Encrypt and send the file content
	buf := make([]byte, 4096)
	for {
		n, err := file.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				log.Println("File sent successfully")
				return nil, err
			}
			log.Println("File read error:", err)
			return nil, err
		}
		return buf[:n], nil
	}
}

func startReceiver(port string) net.Conn {
	// Create a socket for listening
	log.Println("Listener starting...")
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	log.Println("port:", port)
	if err != nil {
		log.Println("Listen error:", err)
		return nil
	}
	defer listener.Close()
	log.Println("Receiver starting...")

	// Accept connection
	conn, err := listener.Accept()
	if err != nil {
		log.Println("Accept error:", err)
		return nil
	}
	log.Println("Receiver connected")
	return conn
}

func receiveMessage(conn net.Conn) []string {
	// Receive data and store it in a variable
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read error:", err)
		return nil
	}

	receivedData := string(buf[:n])
	params := strings.Split(receivedData, ",")
	fmt.Println("Received data:", params)
	return params
}

func send_c(data []byte, U1H *Collosopn_Resistant_Hash, U2H *Collosopn_Resistant_Hash, sys *SystemSetup, pk_2 *PublicKey_2, ppk1 *PPK_1) (*PublicKey_1, *SecretKey_1, *Signcryption) {
	pk_1, sk_1, SigC := c_init()

	pk_1, sk_1, U1H.Hash2 = sys.KeyGenerationUser1(ppk1, U1H) //输出的是user1的（公钥pk_1，私钥sk_1）

	//Signcryption Phase  （签密算法：是加密+签名的结合体），由客户端执行，假设User1执行。

	SigC, U1H.Hash3, U1H.Hash4 = sys.Signcryption(data, U1H, U2H, sk_1, pk_2) //文件的加密在这个函数中，注意在加密之前对文件进行处理。
	return pk_1, sk_1, SigC
}

func c_init() (*PublicKey_1, *SecretKey_1, *Signcryption) {
	//Key Generation Phase (User1) 密钥生成，我协议采用的是公钥密码算法，所以每个用户都有自己的（公钥，私钥），这一部分由客户端执行。
	pk_1 := new(PublicKey_1)
	sk_1 := new(SecretKey_1)
	SigC := new(Signcryption)
	return pk_1, sk_1, SigC
}

// 部署在客户端1上
func (sys *SystemSetup) PPKGenerationUser1() (*PPK_1, *big.Int) {

	ppk1 := new(PPK_1)
	U1H := new(Collosopn_Resistant_Hash)
	r := new(big.Int)
	tmpBig := new(big.Int)

	r, ppk1.R = RandGen(sys)

	H1str := "user1" + ppk1.R.String() + sys.P_pub.String()
	U1H.Hash1 = HashNormal(H1str)
	tmpBig.Mul(sys.s, U1H.Hash1)
	tmpBig.Add(r, tmpBig)
	ppk1.d = tmpBig
	println("ppk1.R:")
	println(len(ppk1.R.Bytes()))
	println(ppk1.R.Bytes())
	println("ppk1.d:")
	println(len(ppk1.d.Bytes()))
	println(ppk1.d.Bytes())
	println(base64.StdEncoding.EncodeToString(append(ppk1.R.Bytes(), ppk1.d.Bytes()...)))
	//test
	return ppk1, U1H.Hash1
}

// 部署在客户端1上
func (sys *SystemSetup) KeyGenerationUser1(ppk1 *PPK_1, U1H *Collosopn_Resistant_Hash) (*PublicKey_1, *SecretKey_1, *big.Int) {

	pk_1 := new(PublicKey_1)
	sk_1 := new(SecretKey_1)
	X := new(big.Int)
	tmpBig := new(big.Int)

	sk_1.x, X = RandGen(sys)
	sk_1.d = ppk1.d

	H2str := "user1" + X.String()
	U1H.Hash2 = HashNormal(H2str)
	tmpBig = sys.PointMul(U1H.Hash2, X)
	tmpBig = sys.PointAdd(ppk1.R, tmpBig)
	pk_1.Q = tmpBig
	pk_1.R = ppk1.R

	return pk_1, sk_1, U1H.Hash2
}

// 假设客户端1签密，部署在客户端1上
func (sys *SystemSetup) Signcryption(data []byte, U1H *Collosopn_Resistant_Hash, U2H *Collosopn_Resistant_Hash, sk_1 *SecretKey_1, pk_2 *PublicKey_2) (*Signcryption, *big.Int, *big.Int) {

	var err error
	SigC := new(Signcryption)
	lambda := new(big.Int)
	u := new(big.Int)
	tmpbig := new(big.Int)
	tmpbig1 := new(big.Int)

	SigC.M = string(data) //Original file content
	//SigC.T = strconv.FormatInt(time.Now().UnixNano(), 10)
	fmt.Println("Original file content:", SigC.M)

	lambda, SigC.c2 = RandGen(sys)
	tmpbig = sys.PointMul(U2H.Hash1, sys.P_pub)
	tmpbig = sys.PointAdd(pk_2.Q, tmpbig)
	tmpbig = sys.PointMul(lambda, tmpbig)
	U1H.Hash4 = HashNormal(tmpbig.String())

	SigC.c1, err = ByteXOR(U1H.Hash4.Bytes(), []byte(SigC.M))
	if err != nil {
		fmt.Println("Error:", err)
	}

	u, SigC.U = RandGen(sys)

	tmpbig1.Mul(U1H.Hash2, sk_1.x)
	tmpbig1.Add(sk_1.d, tmpbig1)
	U1H.Hash3 = HashNormal(tmpbig1.String())
	tmpbig1.Mul(U1H.Hash3, tmpbig1)
	tmpbig1.Add(u, tmpbig1)
	SigC.v = tmpbig1

	return SigC, U1H.Hash3, U1H.Hash4
}

func ByteXOR(data1, data2 []byte) ([]byte, error) {

	len1, len2 := len(data1), len(data2)

	maxLen := len1
	if len2 > len1 {
		maxLen = len2
	}

	result := make([]byte, maxLen)

	for i := 0; i < maxLen; i++ {
		var byte1, byte2 byte

		if i < len1 {
			byte1 = data1[i]
		}
		if i < len2 {
			byte2 = data2[i]
		}

		result[i] = byte1 ^ byte2
	}
	return result, nil
}

func client2(selectedDirPath string, sender_IP string, senderPort string, U2H *Collosopn_Resistant_Hash, receiver_port string) {
	pk_2, _ := r_init()
	sys := setup_client()
	var params []string

	message := joinParams(U2H.Hash1.String(), U2H.Hash2.String(), U2H.Hash3.String(), U2H.Hash4.String(), pk_2.Q.String(), pk_2.R.String())

	log.Println("sender_IP:")

	conn1 := createConnection(sender_IP, senderPort)

	log.Println("sender_IP:", sender_IP)
	log.Println("senderPort:", senderPort)

	if conn1 != nil {
		sendMessage(conn1, message)
		conn1.Close()
	}
	//发送给客户端的参数
	conn2 := startReceiver(receiver_port)
	if conn2 != nil {
		params = receiveMessage(conn2)
		conn2.Close()
	}
	pk_1_q, _ := new(big.Int).SetString(params[0], 10)
	pk_1_R, _ := new(big.Int).SetString(params[1], 10)
	pk_1 := &PublicKey_1{
		Q: pk_1_q,
		R: pk_1_R,
	}
	SigC_M := params[2]
	SigC_T := params[3]
	SigC_c1, _ := new(big.Int).SetString(params[4], 10)
	SigC_c2, _ := new(big.Int).SetString(params[5], 10)
	SigC_U, _ := new(big.Int).SetString(params[6], 10)
	SigC_v, _ := new(big.Int).SetString(params[7], 10)
	SigC := &Signcryption{
		M:  SigC_M,
		T:  SigC_T,
		c1: SigC_c1.Bytes(),
		c2: SigC_c2,
		U:  SigC_U,
		v:  SigC_v,
	}
	U1_H_Hash1, _ := new(big.Int).SetString(params[8], 10)
	U1_H_Hash2, _ := new(big.Int).SetString(params[9], 10)
	U1_H_Hash3, _ := new(big.Int).SetString(params[10], 10)
	U1_H_Hash4, _ := new(big.Int).SetString(params[11], 10)
	U1H := &Collosopn_Resistant_Hash{
		Hash1: U1_H_Hash1,
		Hash2: U1_H_Hash2,
		Hash3: U1_H_Hash3,
		Hash4: U1_H_Hash4,
	}
	//从客户端2接收到的参数
	var UnSigC string
	var err error
	_, sk_2 := r_init()
	left := sys.PointMul(SigC.v, sys.P)
	right := sys.PointMul(U1H.Hash1, sys.P_pub)
	right = sys.PointAdd(pk_1.Q, right)
	right = sys.PointMul(U1H.Hash3, right)
	right = sys.PointAdd(SigC.U, right)
	fmt.Println(left.Cmp(right))

	if left.Cmp(right) == 0 {
		UnSigC = sys.UnSigncryption(SigC, U2H, sk_2)
		fmt.Println("Decrypted content:", UnSigC)
	} else {
		OutputError(err)
	}

	//_, UnSigC := recv_u(U1H, U2H, left, right, sys, SigC, pk_1, ppk2)
	changeFile(selectedDirPath, UnSigC)
}
func (sys *SystemSetup) PPKGenerationUser2() (*PPK_2, *big.Int) {
	ppk2 := new(PPK_2)
	U2H := new(Collosopn_Resistant_Hash)
	r := new(big.Int)
	tmpBig := new(big.Int)

	r, ppk2.R = RandGen(sys)

	H1str := "user2" + ppk2.R.String() + sys.P_pub.String()
	U2H.Hash1 = HashNormal(H1str)
	tmpBig.Mul(sys.s, U2H.Hash1)
	tmpBig.Add(r, tmpBig)
	ppk2.d = tmpBig
	println("ppk2.R:")
	println(len(ppk2.R.Bytes()))
	println(ppk2.R.Bytes())
	println("ppk2.d:")
	println(len(ppk2.d.Bytes()))
	println(ppk2.d.Bytes())
	println(base64.StdEncoding.EncodeToString(append(ppk2.R.Bytes(), ppk2.d.Bytes()...)))
	return ppk2, U2H.Hash1
}

func changeFile(savePath string, UnsigC string) {
	file, err := os.Create(savePath + "/" + "filename")
	if err != nil {
		fmt.Println("File create error:", err)
		return
	}
	defer file.Close()
	_, err = file.Write([]byte(UnsigC))
	if err != nil {
		fmt.Println("File write error:", err)
		return
	}

}

func r_init() (*PublicKey_2, *SecretKey_2) {
	//Key Generation Phase (User2) 密钥生成。这一部分由客户端执行。
	pk_2 := new(PublicKey_2)
	sk_2 := new(SecretKey_2)
	return pk_2, sk_2
}

//func recv_u(U1H *Collosopn_Resistant_Hash, U2H *Collosopn_Resistant_Hash, left *big.Int, right *big.Int, sys *SystemSetup, SigC *Signcryption, pk_1 *PublicKey_1) (*PublicKey_2, string) {
//	pk_2, sk_2 := r_init()
//
//	//todo equal 1
//	left = sys.PointMul(ppk2.d, sys.P)
//	right = sys.PointMul(U2H.Hash1, sys.P_pub)
//	right = sys.PointAdd(right, ppk2.R)
//	fmt.Println(left.Cmp(right))
//
//	pk_2, sk_2, U2H.Hash2 = sys.KeyGenerationUser2(ppk2, U2H)
//
//	//UnSigncryption Phase （解签密算法：对签密算法的验证和解密），由客户端执行。假设User2执行
//	var UnSigC string
//	var err error
//
//	//todo equal 3
//	left = sys.PointMul(SigC.v, sys.P)
//	right = sys.PointMul(U1H.Hash1, sys.P_pub)
//	right = sys.PointAdd(pk_1.Q, right)
//	right = sys.PointMul(U1H.Hash3, right)
//	right = sys.PointAdd(SigC.U, right)
//	fmt.Println(left.Cmp(right))
//
//	if left.Cmp(right) == 0 {
//		UnSigC = sys.UnSigncryption(SigC, U2H, sk_2)
//		fmt.Println("Decrypted content:", UnSigC)
//	} else {
//		OutputError(err)
//	}
//	return pk_2, UnSigC
//}

// 部署在客户端2
func (sys *SystemSetup) KeyGenerationUser2(ppk2 *PPK_2, U2H *Collosopn_Resistant_Hash) (*PublicKey_2, *SecretKey_2, *big.Int) {

	pk_2 := new(PublicKey_2)
	sk_2 := new(SecretKey_2)
	X := new(big.Int)
	tmpBig := new(big.Int)

	sk_2.x, X = RandGen(sys)
	sk_2.d = ppk2.d

	H2str := "user2" + X.String()
	U2H.Hash2 = HashNormal(H2str)
	tmpBig = sys.PointMul(U2H.Hash2, X)
	tmpBig = sys.PointAdd(ppk2.R, tmpBig)
	pk_2.Q = tmpBig
	pk_2.R = ppk2.R

	return pk_2, sk_2, U2H.Hash2
}

// 假设客户端2解签密，部署在客户端2上
func (sys *SystemSetup) UnSigncryption(SigC *Signcryption, U2H *Collosopn_Resistant_Hash, sk_2 *SecretKey_2) string {

	tmpbig1 := new(big.Int)
	var tmpbig2 []byte
	var UnSignC string
	var err error

	tmpbig1.Mul(U2H.Hash2, sk_2.x)
	tmpbig1.Add(sk_2.d, tmpbig1)
	tmpbig1 = sys.PointMul(tmpbig1, SigC.c2)
	U2H.Hash4 = HashNormal(tmpbig1.String())

	tmpbig2, err = ByteXOR(U2H.Hash4.Bytes(), SigC.c1)
	if err != nil {
		fmt.Println("Error:", err)
	}
	UnSignC = string(tmpbig2)

	return UnSignC
}

func setup_client() *SystemSetup {
	curve := elliptic.P256()
	CurveParams := curve.Params()

	sys := new(SystemSetup)
	sys.cp = CurveParams
	sys.curve = curve
	sys.P = new(big.Int)
	sys.P = sys.P.SetBytes(elliptic.Marshal(curve, CurveParams.Gx, CurveParams.Gy))

	sys.q = CurveParams.P

	sys.s, sys.P_pub = RandGen(sys)

	return sys
}

// 三个端都需要
func RandGen(sys *SystemSetup) (*big.Int, *big.Int) {
	var point_x, point_y *big.Int
	var point_byte []byte
	GenByZq := new(big.Int)
	ScalarMulResult := new(big.Int)
	var err error
	GenByZq, err = rand.Int(rand.Reader, sys.q)
	OutputError(err)

	point_x, point_y = sys.cp.ScalarBaseMult(GenByZq.Bytes())
	point_byte = elliptic.Marshal(sys.curve, point_x, point_y)
	ScalarMulResult = ScalarMulResult.SetBytes(point_byte)

	return GenByZq, ScalarMulResult
}

// 三个端都需要
func (sys *SystemSetup) PointMul(x, P *big.Int) *big.Int {
	var Point_x *big.Int
	var Point_y *big.Int

	Point := new(big.Int)

	Point_x, Point_y = elliptic.Unmarshal(sys.curve, P.Bytes())
	Point_x, Point_y = sys.cp.ScalarMult(Point_x, Point_y, x.Bytes())

	Point = Point.SetBytes(elliptic.Marshal(sys.curve, Point_x, Point_y))

	return Point
}

// 三个端都需要
func (sys *SystemSetup) PointAdd(R, P *big.Int) *big.Int {
	var Point1_x, Point2_x *big.Int
	var Point1_y, Point2_y *big.Int

	Point := new(big.Int)

	Point1_x, Point1_y = elliptic.Unmarshal(sys.curve, R.Bytes())
	Point2_x, Point2_y = elliptic.Unmarshal(sys.curve, P.Bytes())

	Point_x, Point_y := sys.cp.Add(Point1_x, Point1_y, Point2_x, Point2_y)
	Point = Point.SetBytes(elliptic.Marshal(sys.curve, Point_x, Point_y))

	return Point

}

// 三个端都需要
func OutputError(err error) {
	if err != nil {
		fmt.Println(err)
	}

}

// 三个端都需要
func HashNormal(hStr string) *big.Int {
	H := sha256.New()
	H.Write([]byte(hStr))

	Hbig := new(big.Int)
	Hbig.SetBytes(H.Sum(nil))

	return Hbig
}
