package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
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

func main() {
	U1_H := new(Collosopn_Resistant_Hash)
	U2_H := new(Collosopn_Resistant_Hash)
	left := new(big.Int)
	right := new(big.Int)

	//Setup Phase  (系统的初始化)，对应论文中的Setup Phase,主要是为了初始化协议中算法必需的一些参数。这一部分由服务器执行。
	sys := setup()   //这里的Setup函数在后面写好了，所以直接调用

	//PPK Generation Phase (User1) (部分密钥生成),这一部分由服务器执行。
	ppk_1 := new(PPK_1)
	ppk_1, U1_H.Hash1 = sys.PPKGenerationUser1()  //直接调用

	//Key Generation Phase (User1) 密钥生成，我协议采用的是公钥密码算法，所以每个用户都有自己的（公钥，私钥），这一部分由客户端执行。
	pk_1 := new(PublicKey_1)
	sk_1 := new(SecretKey_1)

	//这里是协议中一个安全防护措施，客户端用于判断服务器分发给它的ppk_1的有效性。由客户端执行。
	//todo equal 1
	left = sys.PointMul(ppk_1.d, sys.P)
	right = sys.PointMul(U1_H.Hash1, sys.P_pub)
	right = sys.PointAdd(right, ppk_1.R)
	fmt.Println(left.Cmp(right))   //只有输出结果为0，才有效，这里在系统中可输出一个提示，你们自己定。

	pk_1, sk_1, U1_H.Hash2 = sys.KeyGenerationUser1(ppk_1,U1_H)  //输出的是user1的（公钥pk_1，私钥sk_1）

	//PPK Generation Phase (User2) 同上
	ppk_2 := new(PPK_2)
	ppk_2, U2_H.Hash1 = sys.PPKGenerationUser2()

	//todo equal 1
	left = sys.PointMul(ppk_2.d, sys.P)
	right = sys.PointMul(U2_H.Hash1, sys.P_pub)
	right = sys.PointAdd(right, ppk_2.R)
	fmt.Println(left.Cmp(right))

	//Key Generation Phase (User2) 同上
	pk_2 := new(PublicKey_2)
	sk_2 := new(SecretKey_2)
	pk_2, sk_2, U2_H.Hash2 = sys.KeyGenerationUser2(ppk_2, U2_H)

	//todo equal 2
	left = sys.PointMul(sk_2.d, sys.P)
	right = sys.PointMul(U2_H.Hash1, sys.P_pub)
	right = sys.PointAdd(right, pk_2.R)
	fmt.Println(left.Cmp(right))

	//Signcryption Phase  （签密算法：是加密+签名的结合体），由客户端执行，假设User1执行。
	SigC := new(Signcryption)
	SigC, U1_H.Hash3, U1_H.Hash4 = sys.Signcryption(U1_H, U2_H, sk_1, pk_2) //文件的加密在这个函数中，注意在加密之前对文件进行处理。

	//UnSigncryption Phase （解签密算法：对签密算法的验证和解密），由客户端执行。假设User2执行
	var UnSigC string
	var err error

	//todo equal 3
	left = sys.PointMul(SigC.v, sys.P)
	right = sys.PointMul(U1_H.Hash1, sys.P_pub)
	right = sys.PointAdd(pk_1.Q, right)
	right = sys.PointMul(U1_H.Hash3, right)
	right = sys.PointAdd(SigC.U, right)
	fmt.Println(left.Cmp(right))

	if left.Cmp(right) == 0 {
		UnSigC = sys.UnSigncryption(SigC, U2_H, sk_2)
		fmt.Println("Decrypted content:", UnSigC)
	} else {
		OutputError(err)
	}

}

//系统初始化，部署在服务器上
func setup() *SystemSetup {
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

//部署在客户端1上
func (sys *SystemSetup) PPKGenerationUser1() (*PPK_1, *big.Int) {

	ppk_1 := new(PPK_1)
	U1_H := new(Collosopn_Resistant_Hash)
	r := new(big.Int)
	tmpBig := new(big.Int)

	r, ppk_1.R = RandGen(sys)

	H1str := "user1" + ppk_1.R.String() + sys.P_pub.String()
	U1_H.Hash1 = HashNormal(H1str)
	tmpBig.Mul(sys.s, U1_H.Hash1)
	tmpBig.Add(r, tmpBig)
	ppk_1.d = tmpBig

	return ppk_1, U1_H.Hash1
}

//部署在客户端1上
func (sys *SystemSetup) KeyGenerationUser1(ppk_1 *PPK_1, U1_H *Collosopn_Resistant_Hash) (*PublicKey_1, *SecretKey_1, *big.Int) {

	pk_1 := new(PublicKey_1)
	sk_1 := new(SecretKey_1)
	X := new(big.Int)
	tmpBig := new(big.Int)

	sk_1.x, X = RandGen(sys)
	sk_1.d = ppk_1.d

	H2str := "user1" + X.String()
	U1_H.Hash2 = HashNormal(H2str)
	tmpBig = sys.PointMul(U1_H.Hash2, X)
	tmpBig = sys.PointAdd(ppk_1.R, tmpBig)
	pk_1.Q = tmpBig
	pk_1.R = ppk_1.R

	return pk_1, sk_1, U1_H.Hash2
}


//部署在客户端2
func (sys *SystemSetup) PPKGenerationUser2() (*PPK_2, *big.Int) {

	ppk_2 := new(PPK_2)
	U2_H := new(Collosopn_Resistant_Hash)
	r := new(big.Int)
	tmpBig := new(big.Int)

	r, ppk_2.R = RandGen(sys)

	H1str := "user2" + ppk_2.R.String() + sys.P_pub.String()
	U2_H.Hash1 = HashNormal(H1str)
	tmpBig.Mul(sys.s, U2_H.Hash1)
	tmpBig.Add(r, tmpBig)
	ppk_2.d = tmpBig

	return ppk_2, U2_H.Hash1
}

//部署在客户端2
func (sys *SystemSetup) KeyGenerationUser2(ppk_2 *PPK_2, U2_H *Collosopn_Resistant_Hash) (*PublicKey_2, *SecretKey_2, *big.Int) {

	pk_2 := new(PublicKey_2)
	sk_2 := new(SecretKey_2)
	X := new(big.Int)
	tmpBig := new(big.Int)

	sk_2.x, X = RandGen(sys)
	sk_2.d = ppk_2.d

	H2str := "user2" + X.String()
	U2_H.Hash2 = HashNormal(H2str)
	tmpBig = sys.PointMul(U2_H.Hash2, X)
	tmpBig = sys.PointAdd(ppk_2.R, tmpBig)
	pk_2.Q = tmpBig
	pk_2.R = ppk_2.R

	return pk_2, sk_2, U2_H.Hash2
}

//假设客户端1签密，部署在客户端1上
func (sys *SystemSetup) Signcryption(U1_H *Collosopn_Resistant_Hash, U2_H *Collosopn_Resistant_Hash, sk_1 *SecretKey_1, pk_2 *PublicKey_2) (*Signcryption, *big.Int, *big.Int) {

	var err error
	SigC := new(Signcryption)
	lambda := new(big.Int)
	u := new(big.Int)
	tmpbig := new(big.Int)
	tmpbig1 := new(big.Int)

	SigC.M = "This is a test code, and the processed files can be placed later." //Original file content
	//SigC.T = strconv.FormatInt(time.Now().UnixNano(), 10)
	fmt.Println("Original file content:", SigC.M)

	lambda, SigC.c2 = RandGen(sys)
	tmpbig = sys.PointMul(U2_H.Hash1, sys.P_pub)
	tmpbig = sys.PointAdd(pk_2.Q, tmpbig)
	tmpbig = sys.PointMul(lambda, tmpbig)
	U1_H.Hash4 = HashNormal(tmpbig.String())

	SigC.c1, err = ByteXOR(U1_H.Hash4.Bytes(), []byte(SigC.M))
	if err != nil {
		fmt.Println("Error:", err)
	}

	u, SigC.U = RandGen(sys)

	tmpbig1.Mul(U1_H.Hash2, sk_1.x)
	tmpbig1.Add(sk_1.d, tmpbig1)
	U1_H.Hash3 = HashNormal(tmpbig1.String())
	tmpbig1.Mul(U1_H.Hash3, tmpbig1)
	tmpbig1.Add(u, tmpbig1)
	SigC.v = tmpbig1

	return SigC, U1_H.Hash3, U1_H.Hash4
}

//假设客户端2解签密，部署在客户端2上
func (sys *SystemSetup) UnSigncryption(SigC *Signcryption, U2_H *Collosopn_Resistant_Hash, sk_2 *SecretKey_2) string {

	tmpbig1 := new(big.Int)
	var tmpbig2 []byte
	var UnSignC string
	var err error

	tmpbig1.Mul(U2_H.Hash2, sk_2.x)
	tmpbig1.Add(sk_2.d, tmpbig1)
	tmpbig1 = sys.PointMul(tmpbig1, SigC.c2)
	U2_H.Hash4 = HashNormal(tmpbig1.String())

	tmpbig2, err = ByteXOR(U2_H.Hash4.Bytes(), SigC.c1)
	if err != nil {
		fmt.Println("Error:", err)
	}
	UnSignC = string(tmpbig2)

	return UnSignC
}

//三个端都需要
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

//三个端都需要
func (sys *SystemSetup) PointMul(x, P *big.Int) *big.Int {
	var Point_x *big.Int
	var Point_y *big.Int

	Point := new(big.Int)

	Point_x, Point_y = elliptic.Unmarshal(sys.curve, P.Bytes())
	Point_x, Point_y = sys.cp.ScalarMult(Point_x, Point_y, x.Bytes())

	Point = Point.SetBytes(elliptic.Marshal(sys.curve, Point_x, Point_y))

	return Point
}

//三个端都需要
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

//三个端都需要
func OutputError(err error) {
	if err != nil {
		fmt.Println(err)
	}

}

//三个端都需要
func HashNormal(hStr string) *big.Int {
	H := sha256.New()
	H.Write([]byte(hStr))

	Hbig := new(big.Int)
	Hbig.SetBytes(H.Sum(nil))

	return Hbig
}

//两个客户端需要
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
