package pkcs7

import (
	"testing"
	"bytes"
	"fmt"
)

func Example1() {
	msg  := []byte("Linux is dead")	// 13
	bs   := 32
	pmsg, err := Pad(msg, bs)
	if err != nil {
	}
	// Omitted: Encrypt -> HMAC -> Tx -> Rx -> Auth
	
	umsg, err  := Unpad(pmsg, bs)
	if err != nil {
	}
	fmt.Println(pmsg)
	fmt.Println(umsg)
}

type fn func([]byte, int) ([]byte, error)
func r(s string, n int) []byte {
	return bytes.Repeat([]byte(s), n)
}

func do(bs int, m []byte, p []byte, t *testing.T) {
	mp, err := Pad(m, bs)
	if err != nil {
		t.Log("pad",err)
		t.Fail()
	}
	if !bytes.Equal(mp, append(m, p...)) {
		t.Logf("pad:\nm=%v\np=%v\nmp=%v\nex=%v\n\n",m,p,mp, append(m, p...))
		t.Fail()
	}
	am, err := Unpad(mp, bs)
	if err != nil {
		t.Log("unpad",err)
		t.Fail()
	}
	if !bytes.Equal(am, m) {
		t.Logf("unpad:\nac=%v\nex=%v\n",am, m)
		t.Fail()
	}
}

/* awk to gen tables
{<
for (i in 16 32 64 128 160 192 240 248 256) {
	echo $i | awk '
{
	bs=$1
	for (i=0;i<256;i++) {
		padlen = bs - i % bs
		padval = padlen % bs
		printf "func Test%02dx%03d(t *testing.T){ ", bs, i
		printf "do(%d, r(\"A\",%2d), r(\"\\x%02x\",%2d), t)}\n", bs, i, padval, padlen
	}
}'
}}
Edit /(.+\n)/+,d 
*/

func TestEdge(t *testing.T){
	in := []byte("perfectlyaligned")
	expect := append(in, bytes.Repeat([]byte{0}, 16)...)
	actual, err := Pad(in, 16)
	if err != nil {
		t.Logf("pad: unexpected err=%s\n", err)
		t.Fail()
	}
	if !bytes.Equal(expect, actual) {
		t.Logf("pad: expect=%#x\nactual=%#x\n\n",expect, actual)
		t.Fail()
	}
	in2, err := Unpad(actual, 16)
	if err != nil {
		t.Logf("unpad: unexpected err=%s\n", err)
		t.Fail()
	}
	if !bytes.Equal(in2, in) {
		t.Logf("unpad: expect=%#x\nactual=%#x\n\n",in, in2)
		t.Fail()
	}
}

func Test16x000(t *testing.T){ do(16, r("A", 0), r("\x00",16), t)}
func Test16x001(t *testing.T){ do(16, r("A", 1), r("\x0f",15), t)}
func Test16x002(t *testing.T){ do(16, r("A", 2), r("\x0e",14), t)}
func Test16x003(t *testing.T){ do(16, r("A", 3), r("\x0d",13), t)}
func Test16x004(t *testing.T){ do(16, r("A", 4), r("\x0c",12), t)}
func Test16x005(t *testing.T){ do(16, r("A", 5), r("\x0b",11), t)}
func Test16x006(t *testing.T){ do(16, r("A", 6), r("\x0a",10), t)}
func Test16x007(t *testing.T){ do(16, r("A", 7), r("\x09", 9), t)}
func Test16x008(t *testing.T){ do(16, r("A", 8), r("\x08", 8), t)}
func Test16x009(t *testing.T){ do(16, r("A", 9), r("\x07", 7), t)}
func Test16x010(t *testing.T){ do(16, r("A",10), r("\x06", 6), t)}
func Test16x011(t *testing.T){ do(16, r("A",11), r("\x05", 5), t)}
func Test16x012(t *testing.T){ do(16, r("A",12), r("\x04", 4), t)}
func Test16x013(t *testing.T){ do(16, r("A",13), r("\x03", 3), t)}
func Test16x014(t *testing.T){ do(16, r("A",14), r("\x02", 2), t)}
func Test16x015(t *testing.T){ do(16, r("A",15), r("\x01", 1), t)}
func Test16x016(t *testing.T){ do(16, r("A",16), r("\x00",16), t)}
func Test16x017(t *testing.T){ do(16, r("A",17), r("\x0f",15), t)}
func Test16x018(t *testing.T){ do(16, r("A",18), r("\x0e",14), t)}
func Test16x019(t *testing.T){ do(16, r("A",19), r("\x0d",13), t)}
func Test16x020(t *testing.T){ do(16, r("A",20), r("\x0c",12), t)}
func Test16x021(t *testing.T){ do(16, r("A",21), r("\x0b",11), t)}
func Test16x022(t *testing.T){ do(16, r("A",22), r("\x0a",10), t)}
func Test16x023(t *testing.T){ do(16, r("A",23), r("\x09", 9), t)}
func Test16x024(t *testing.T){ do(16, r("A",24), r("\x08", 8), t)}
func Test16x025(t *testing.T){ do(16, r("A",25), r("\x07", 7), t)}
func Test16x026(t *testing.T){ do(16, r("A",26), r("\x06", 6), t)}
func Test16x027(t *testing.T){ do(16, r("A",27), r("\x05", 5), t)}
func Test16x028(t *testing.T){ do(16, r("A",28), r("\x04", 4), t)}
func Test16x029(t *testing.T){ do(16, r("A",29), r("\x03", 3), t)}
func Test16x030(t *testing.T){ do(16, r("A",30), r("\x02", 2), t)}
func Test16x031(t *testing.T){ do(16, r("A",31), r("\x01", 1), t)}
func Test16x032(t *testing.T){ do(16, r("A",32), r("\x00",16), t)}
func Test16x033(t *testing.T){ do(16, r("A",33), r("\x0f",15), t)}
func Test16x034(t *testing.T){ do(16, r("A",34), r("\x0e",14), t)}
func Test16x035(t *testing.T){ do(16, r("A",35), r("\x0d",13), t)}
func Test16x036(t *testing.T){ do(16, r("A",36), r("\x0c",12), t)}
func Test16x037(t *testing.T){ do(16, r("A",37), r("\x0b",11), t)}
func Test16x038(t *testing.T){ do(16, r("A",38), r("\x0a",10), t)}
func Test16x039(t *testing.T){ do(16, r("A",39), r("\x09", 9), t)}
func Test16x040(t *testing.T){ do(16, r("A",40), r("\x08", 8), t)}
func Test16x041(t *testing.T){ do(16, r("A",41), r("\x07", 7), t)}
func Test16x042(t *testing.T){ do(16, r("A",42), r("\x06", 6), t)}
func Test16x043(t *testing.T){ do(16, r("A",43), r("\x05", 5), t)}
func Test16x044(t *testing.T){ do(16, r("A",44), r("\x04", 4), t)}
func Test16x045(t *testing.T){ do(16, r("A",45), r("\x03", 3), t)}
func Test16x046(t *testing.T){ do(16, r("A",46), r("\x02", 2), t)}
func Test16x047(t *testing.T){ do(16, r("A",47), r("\x01", 1), t)}
func Test16x048(t *testing.T){ do(16, r("A",48), r("\x00",16), t)}
func Test16x049(t *testing.T){ do(16, r("A",49), r("\x0f",15), t)}
func Test16x050(t *testing.T){ do(16, r("A",50), r("\x0e",14), t)}
func Test16x051(t *testing.T){ do(16, r("A",51), r("\x0d",13), t)}
func Test16x052(t *testing.T){ do(16, r("A",52), r("\x0c",12), t)}
func Test16x053(t *testing.T){ do(16, r("A",53), r("\x0b",11), t)}
func Test16x054(t *testing.T){ do(16, r("A",54), r("\x0a",10), t)}
func Test16x055(t *testing.T){ do(16, r("A",55), r("\x09", 9), t)}
func Test16x056(t *testing.T){ do(16, r("A",56), r("\x08", 8), t)}
func Test16x057(t *testing.T){ do(16, r("A",57), r("\x07", 7), t)}
func Test16x058(t *testing.T){ do(16, r("A",58), r("\x06", 6), t)}
func Test16x059(t *testing.T){ do(16, r("A",59), r("\x05", 5), t)}
func Test16x060(t *testing.T){ do(16, r("A",60), r("\x04", 4), t)}
func Test16x061(t *testing.T){ do(16, r("A",61), r("\x03", 3), t)}
func Test16x062(t *testing.T){ do(16, r("A",62), r("\x02", 2), t)}
func Test16x063(t *testing.T){ do(16, r("A",63), r("\x01", 1), t)}
func Test16x064(t *testing.T){ do(16, r("A",64), r("\x00",16), t)}
func Test16x065(t *testing.T){ do(16, r("A",65), r("\x0f",15), t)}
func Test16x066(t *testing.T){ do(16, r("A",66), r("\x0e",14), t)}
func Test16x067(t *testing.T){ do(16, r("A",67), r("\x0d",13), t)}
func Test16x068(t *testing.T){ do(16, r("A",68), r("\x0c",12), t)}
func Test16x069(t *testing.T){ do(16, r("A",69), r("\x0b",11), t)}
func Test16x070(t *testing.T){ do(16, r("A",70), r("\x0a",10), t)}
func Test16x071(t *testing.T){ do(16, r("A",71), r("\x09", 9), t)}
func Test16x072(t *testing.T){ do(16, r("A",72), r("\x08", 8), t)}
func Test16x073(t *testing.T){ do(16, r("A",73), r("\x07", 7), t)}
func Test16x074(t *testing.T){ do(16, r("A",74), r("\x06", 6), t)}
func Test16x075(t *testing.T){ do(16, r("A",75), r("\x05", 5), t)}
func Test16x076(t *testing.T){ do(16, r("A",76), r("\x04", 4), t)}
func Test16x077(t *testing.T){ do(16, r("A",77), r("\x03", 3), t)}
func Test16x078(t *testing.T){ do(16, r("A",78), r("\x02", 2), t)}
func Test16x079(t *testing.T){ do(16, r("A",79), r("\x01", 1), t)}
func Test16x080(t *testing.T){ do(16, r("A",80), r("\x00",16), t)}
func Test16x081(t *testing.T){ do(16, r("A",81), r("\x0f",15), t)}
func Test16x082(t *testing.T){ do(16, r("A",82), r("\x0e",14), t)}
func Test16x083(t *testing.T){ do(16, r("A",83), r("\x0d",13), t)}
func Test16x084(t *testing.T){ do(16, r("A",84), r("\x0c",12), t)}
func Test16x085(t *testing.T){ do(16, r("A",85), r("\x0b",11), t)}
func Test16x086(t *testing.T){ do(16, r("A",86), r("\x0a",10), t)}
func Test16x087(t *testing.T){ do(16, r("A",87), r("\x09", 9), t)}
func Test16x088(t *testing.T){ do(16, r("A",88), r("\x08", 8), t)}
func Test16x089(t *testing.T){ do(16, r("A",89), r("\x07", 7), t)}
func Test16x090(t *testing.T){ do(16, r("A",90), r("\x06", 6), t)}
func Test16x091(t *testing.T){ do(16, r("A",91), r("\x05", 5), t)}
func Test16x092(t *testing.T){ do(16, r("A",92), r("\x04", 4), t)}
func Test16x093(t *testing.T){ do(16, r("A",93), r("\x03", 3), t)}
func Test16x094(t *testing.T){ do(16, r("A",94), r("\x02", 2), t)}
func Test16x095(t *testing.T){ do(16, r("A",95), r("\x01", 1), t)}
func Test16x096(t *testing.T){ do(16, r("A",96), r("\x00",16), t)}
func Test16x097(t *testing.T){ do(16, r("A",97), r("\x0f",15), t)}
func Test16x098(t *testing.T){ do(16, r("A",98), r("\x0e",14), t)}
func Test16x099(t *testing.T){ do(16, r("A",99), r("\x0d",13), t)}
func Test16x100(t *testing.T){ do(16, r("A",100), r("\x0c",12), t)}
func Test16x101(t *testing.T){ do(16, r("A",101), r("\x0b",11), t)}
func Test16x102(t *testing.T){ do(16, r("A",102), r("\x0a",10), t)}
func Test16x103(t *testing.T){ do(16, r("A",103), r("\x09", 9), t)}
func Test16x104(t *testing.T){ do(16, r("A",104), r("\x08", 8), t)}
func Test16x105(t *testing.T){ do(16, r("A",105), r("\x07", 7), t)}
func Test16x106(t *testing.T){ do(16, r("A",106), r("\x06", 6), t)}
func Test16x107(t *testing.T){ do(16, r("A",107), r("\x05", 5), t)}
func Test16x108(t *testing.T){ do(16, r("A",108), r("\x04", 4), t)}
func Test16x109(t *testing.T){ do(16, r("A",109), r("\x03", 3), t)}
func Test16x110(t *testing.T){ do(16, r("A",110), r("\x02", 2), t)}
func Test16x111(t *testing.T){ do(16, r("A",111), r("\x01", 1), t)}
func Test16x112(t *testing.T){ do(16, r("A",112), r("\x00",16), t)}
func Test16x113(t *testing.T){ do(16, r("A",113), r("\x0f",15), t)}
func Test16x114(t *testing.T){ do(16, r("A",114), r("\x0e",14), t)}
func Test16x115(t *testing.T){ do(16, r("A",115), r("\x0d",13), t)}
func Test16x116(t *testing.T){ do(16, r("A",116), r("\x0c",12), t)}
func Test16x117(t *testing.T){ do(16, r("A",117), r("\x0b",11), t)}
func Test16x118(t *testing.T){ do(16, r("A",118), r("\x0a",10), t)}
func Test16x119(t *testing.T){ do(16, r("A",119), r("\x09", 9), t)}
func Test16x120(t *testing.T){ do(16, r("A",120), r("\x08", 8), t)}
func Test16x121(t *testing.T){ do(16, r("A",121), r("\x07", 7), t)}
func Test16x122(t *testing.T){ do(16, r("A",122), r("\x06", 6), t)}
func Test16x123(t *testing.T){ do(16, r("A",123), r("\x05", 5), t)}
func Test16x124(t *testing.T){ do(16, r("A",124), r("\x04", 4), t)}
func Test16x125(t *testing.T){ do(16, r("A",125), r("\x03", 3), t)}
func Test16x126(t *testing.T){ do(16, r("A",126), r("\x02", 2), t)}
func Test16x127(t *testing.T){ do(16, r("A",127), r("\x01", 1), t)}
func Test16x128(t *testing.T){ do(16, r("A",128), r("\x00",16), t)}
func Test16x129(t *testing.T){ do(16, r("A",129), r("\x0f",15), t)}
func Test16x130(t *testing.T){ do(16, r("A",130), r("\x0e",14), t)}
func Test16x131(t *testing.T){ do(16, r("A",131), r("\x0d",13), t)}
func Test16x132(t *testing.T){ do(16, r("A",132), r("\x0c",12), t)}
func Test16x133(t *testing.T){ do(16, r("A",133), r("\x0b",11), t)}
func Test16x134(t *testing.T){ do(16, r("A",134), r("\x0a",10), t)}
func Test16x135(t *testing.T){ do(16, r("A",135), r("\x09", 9), t)}
func Test16x136(t *testing.T){ do(16, r("A",136), r("\x08", 8), t)}
func Test16x137(t *testing.T){ do(16, r("A",137), r("\x07", 7), t)}
func Test16x138(t *testing.T){ do(16, r("A",138), r("\x06", 6), t)}
func Test16x139(t *testing.T){ do(16, r("A",139), r("\x05", 5), t)}
func Test16x140(t *testing.T){ do(16, r("A",140), r("\x04", 4), t)}
func Test16x141(t *testing.T){ do(16, r("A",141), r("\x03", 3), t)}
func Test16x142(t *testing.T){ do(16, r("A",142), r("\x02", 2), t)}
func Test16x143(t *testing.T){ do(16, r("A",143), r("\x01", 1), t)}
func Test16x144(t *testing.T){ do(16, r("A",144), r("\x00",16), t)}
func Test16x145(t *testing.T){ do(16, r("A",145), r("\x0f",15), t)}
func Test16x146(t *testing.T){ do(16, r("A",146), r("\x0e",14), t)}
func Test16x147(t *testing.T){ do(16, r("A",147), r("\x0d",13), t)}
func Test16x148(t *testing.T){ do(16, r("A",148), r("\x0c",12), t)}
func Test16x149(t *testing.T){ do(16, r("A",149), r("\x0b",11), t)}
func Test16x150(t *testing.T){ do(16, r("A",150), r("\x0a",10), t)}
func Test16x151(t *testing.T){ do(16, r("A",151), r("\x09", 9), t)}
func Test16x152(t *testing.T){ do(16, r("A",152), r("\x08", 8), t)}
func Test16x153(t *testing.T){ do(16, r("A",153), r("\x07", 7), t)}
func Test16x154(t *testing.T){ do(16, r("A",154), r("\x06", 6), t)}
func Test16x155(t *testing.T){ do(16, r("A",155), r("\x05", 5), t)}
func Test16x156(t *testing.T){ do(16, r("A",156), r("\x04", 4), t)}
func Test16x157(t *testing.T){ do(16, r("A",157), r("\x03", 3), t)}
func Test16x158(t *testing.T){ do(16, r("A",158), r("\x02", 2), t)}
func Test16x159(t *testing.T){ do(16, r("A",159), r("\x01", 1), t)}
func Test16x160(t *testing.T){ do(16, r("A",160), r("\x00",16), t)}
func Test16x161(t *testing.T){ do(16, r("A",161), r("\x0f",15), t)}
func Test16x162(t *testing.T){ do(16, r("A",162), r("\x0e",14), t)}
func Test16x163(t *testing.T){ do(16, r("A",163), r("\x0d",13), t)}
func Test16x164(t *testing.T){ do(16, r("A",164), r("\x0c",12), t)}
func Test16x165(t *testing.T){ do(16, r("A",165), r("\x0b",11), t)}
func Test16x166(t *testing.T){ do(16, r("A",166), r("\x0a",10), t)}
func Test16x167(t *testing.T){ do(16, r("A",167), r("\x09", 9), t)}
func Test16x168(t *testing.T){ do(16, r("A",168), r("\x08", 8), t)}
func Test16x169(t *testing.T){ do(16, r("A",169), r("\x07", 7), t)}
func Test16x170(t *testing.T){ do(16, r("A",170), r("\x06", 6), t)}
func Test16x171(t *testing.T){ do(16, r("A",171), r("\x05", 5), t)}
func Test16x172(t *testing.T){ do(16, r("A",172), r("\x04", 4), t)}
func Test16x173(t *testing.T){ do(16, r("A",173), r("\x03", 3), t)}
func Test16x174(t *testing.T){ do(16, r("A",174), r("\x02", 2), t)}
func Test16x175(t *testing.T){ do(16, r("A",175), r("\x01", 1), t)}
func Test16x176(t *testing.T){ do(16, r("A",176), r("\x00",16), t)}
func Test16x177(t *testing.T){ do(16, r("A",177), r("\x0f",15), t)}
func Test16x178(t *testing.T){ do(16, r("A",178), r("\x0e",14), t)}
func Test16x179(t *testing.T){ do(16, r("A",179), r("\x0d",13), t)}
func Test16x180(t *testing.T){ do(16, r("A",180), r("\x0c",12), t)}
func Test16x181(t *testing.T){ do(16, r("A",181), r("\x0b",11), t)}
func Test16x182(t *testing.T){ do(16, r("A",182), r("\x0a",10), t)}
func Test16x183(t *testing.T){ do(16, r("A",183), r("\x09", 9), t)}
func Test16x184(t *testing.T){ do(16, r("A",184), r("\x08", 8), t)}
func Test16x185(t *testing.T){ do(16, r("A",185), r("\x07", 7), t)}
func Test16x186(t *testing.T){ do(16, r("A",186), r("\x06", 6), t)}
func Test16x187(t *testing.T){ do(16, r("A",187), r("\x05", 5), t)}
func Test16x188(t *testing.T){ do(16, r("A",188), r("\x04", 4), t)}
func Test16x189(t *testing.T){ do(16, r("A",189), r("\x03", 3), t)}
func Test16x190(t *testing.T){ do(16, r("A",190), r("\x02", 2), t)}
func Test16x191(t *testing.T){ do(16, r("A",191), r("\x01", 1), t)}
func Test16x192(t *testing.T){ do(16, r("A",192), r("\x00",16), t)}
func Test16x193(t *testing.T){ do(16, r("A",193), r("\x0f",15), t)}
func Test16x194(t *testing.T){ do(16, r("A",194), r("\x0e",14), t)}
func Test16x195(t *testing.T){ do(16, r("A",195), r("\x0d",13), t)}
func Test16x196(t *testing.T){ do(16, r("A",196), r("\x0c",12), t)}
func Test16x197(t *testing.T){ do(16, r("A",197), r("\x0b",11), t)}
func Test16x198(t *testing.T){ do(16, r("A",198), r("\x0a",10), t)}
func Test16x199(t *testing.T){ do(16, r("A",199), r("\x09", 9), t)}
func Test16x200(t *testing.T){ do(16, r("A",200), r("\x08", 8), t)}
func Test16x201(t *testing.T){ do(16, r("A",201), r("\x07", 7), t)}
func Test16x202(t *testing.T){ do(16, r("A",202), r("\x06", 6), t)}
func Test16x203(t *testing.T){ do(16, r("A",203), r("\x05", 5), t)}
func Test16x204(t *testing.T){ do(16, r("A",204), r("\x04", 4), t)}
func Test16x205(t *testing.T){ do(16, r("A",205), r("\x03", 3), t)}
func Test16x206(t *testing.T){ do(16, r("A",206), r("\x02", 2), t)}
func Test16x207(t *testing.T){ do(16, r("A",207), r("\x01", 1), t)}
func Test16x208(t *testing.T){ do(16, r("A",208), r("\x00",16), t)}
func Test16x209(t *testing.T){ do(16, r("A",209), r("\x0f",15), t)}
func Test16x210(t *testing.T){ do(16, r("A",210), r("\x0e",14), t)}
func Test16x211(t *testing.T){ do(16, r("A",211), r("\x0d",13), t)}
func Test16x212(t *testing.T){ do(16, r("A",212), r("\x0c",12), t)}
func Test16x213(t *testing.T){ do(16, r("A",213), r("\x0b",11), t)}
func Test16x214(t *testing.T){ do(16, r("A",214), r("\x0a",10), t)}
func Test16x215(t *testing.T){ do(16, r("A",215), r("\x09", 9), t)}
func Test16x216(t *testing.T){ do(16, r("A",216), r("\x08", 8), t)}
func Test16x217(t *testing.T){ do(16, r("A",217), r("\x07", 7), t)}
func Test16x218(t *testing.T){ do(16, r("A",218), r("\x06", 6), t)}
func Test16x219(t *testing.T){ do(16, r("A",219), r("\x05", 5), t)}
func Test16x220(t *testing.T){ do(16, r("A",220), r("\x04", 4), t)}
func Test16x221(t *testing.T){ do(16, r("A",221), r("\x03", 3), t)}
func Test16x222(t *testing.T){ do(16, r("A",222), r("\x02", 2), t)}
func Test16x223(t *testing.T){ do(16, r("A",223), r("\x01", 1), t)}
func Test16x224(t *testing.T){ do(16, r("A",224), r("\x00",16), t)}
func Test16x225(t *testing.T){ do(16, r("A",225), r("\x0f",15), t)}
func Test16x226(t *testing.T){ do(16, r("A",226), r("\x0e",14), t)}
func Test16x227(t *testing.T){ do(16, r("A",227), r("\x0d",13), t)}
func Test16x228(t *testing.T){ do(16, r("A",228), r("\x0c",12), t)}
func Test16x229(t *testing.T){ do(16, r("A",229), r("\x0b",11), t)}
func Test16x230(t *testing.T){ do(16, r("A",230), r("\x0a",10), t)}
func Test16x231(t *testing.T){ do(16, r("A",231), r("\x09", 9), t)}
func Test16x232(t *testing.T){ do(16, r("A",232), r("\x08", 8), t)}
func Test16x233(t *testing.T){ do(16, r("A",233), r("\x07", 7), t)}
func Test16x234(t *testing.T){ do(16, r("A",234), r("\x06", 6), t)}
func Test16x235(t *testing.T){ do(16, r("A",235), r("\x05", 5), t)}
func Test16x236(t *testing.T){ do(16, r("A",236), r("\x04", 4), t)}
func Test16x237(t *testing.T){ do(16, r("A",237), r("\x03", 3), t)}
func Test16x238(t *testing.T){ do(16, r("A",238), r("\x02", 2), t)}
func Test16x239(t *testing.T){ do(16, r("A",239), r("\x01", 1), t)}
func Test16x240(t *testing.T){ do(16, r("A",240), r("\x00",16), t)}
func Test16x241(t *testing.T){ do(16, r("A",241), r("\x0f",15), t)}
func Test16x242(t *testing.T){ do(16, r("A",242), r("\x0e",14), t)}
func Test16x243(t *testing.T){ do(16, r("A",243), r("\x0d",13), t)}
func Test16x244(t *testing.T){ do(16, r("A",244), r("\x0c",12), t)}
func Test16x245(t *testing.T){ do(16, r("A",245), r("\x0b",11), t)}
func Test16x246(t *testing.T){ do(16, r("A",246), r("\x0a",10), t)}
func Test16x247(t *testing.T){ do(16, r("A",247), r("\x09", 9), t)}
func Test16x248(t *testing.T){ do(16, r("A",248), r("\x08", 8), t)}
func Test16x249(t *testing.T){ do(16, r("A",249), r("\x07", 7), t)}
func Test16x250(t *testing.T){ do(16, r("A",250), r("\x06", 6), t)}
func Test16x251(t *testing.T){ do(16, r("A",251), r("\x05", 5), t)}
func Test16x252(t *testing.T){ do(16, r("A",252), r("\x04", 4), t)}
func Test16x253(t *testing.T){ do(16, r("A",253), r("\x03", 3), t)}
func Test16x254(t *testing.T){ do(16, r("A",254), r("\x02", 2), t)}
func Test16x255(t *testing.T){ do(16, r("A",255), r("\x01", 1), t)}
func Test32x000(t *testing.T){ do(32, r("A", 0), r("\x00",32), t)}
func Test32x001(t *testing.T){ do(32, r("A", 1), r("\x1f",31), t)}
func Test32x002(t *testing.T){ do(32, r("A", 2), r("\x1e",30), t)}
func Test32x003(t *testing.T){ do(32, r("A", 3), r("\x1d",29), t)}
func Test32x004(t *testing.T){ do(32, r("A", 4), r("\x1c",28), t)}
func Test32x005(t *testing.T){ do(32, r("A", 5), r("\x1b",27), t)}
func Test32x006(t *testing.T){ do(32, r("A", 6), r("\x1a",26), t)}
func Test32x007(t *testing.T){ do(32, r("A", 7), r("\x19",25), t)}
func Test32x008(t *testing.T){ do(32, r("A", 8), r("\x18",24), t)}
func Test32x009(t *testing.T){ do(32, r("A", 9), r("\x17",23), t)}
func Test32x010(t *testing.T){ do(32, r("A",10), r("\x16",22), t)}
func Test32x011(t *testing.T){ do(32, r("A",11), r("\x15",21), t)}
func Test32x012(t *testing.T){ do(32, r("A",12), r("\x14",20), t)}
func Test32x013(t *testing.T){ do(32, r("A",13), r("\x13",19), t)}
func Test32x014(t *testing.T){ do(32, r("A",14), r("\x12",18), t)}
func Test32x015(t *testing.T){ do(32, r("A",15), r("\x11",17), t)}
func Test32x016(t *testing.T){ do(32, r("A",16), r("\x10",16), t)}
func Test32x017(t *testing.T){ do(32, r("A",17), r("\x0f",15), t)}
func Test32x018(t *testing.T){ do(32, r("A",18), r("\x0e",14), t)}
func Test32x019(t *testing.T){ do(32, r("A",19), r("\x0d",13), t)}
func Test32x020(t *testing.T){ do(32, r("A",20), r("\x0c",12), t)}
func Test32x021(t *testing.T){ do(32, r("A",21), r("\x0b",11), t)}
func Test32x022(t *testing.T){ do(32, r("A",22), r("\x0a",10), t)}
func Test32x023(t *testing.T){ do(32, r("A",23), r("\x09", 9), t)}
func Test32x024(t *testing.T){ do(32, r("A",24), r("\x08", 8), t)}
func Test32x025(t *testing.T){ do(32, r("A",25), r("\x07", 7), t)}
func Test32x026(t *testing.T){ do(32, r("A",26), r("\x06", 6), t)}
func Test32x027(t *testing.T){ do(32, r("A",27), r("\x05", 5), t)}
func Test32x028(t *testing.T){ do(32, r("A",28), r("\x04", 4), t)}
func Test32x029(t *testing.T){ do(32, r("A",29), r("\x03", 3), t)}
func Test32x030(t *testing.T){ do(32, r("A",30), r("\x02", 2), t)}
func Test32x031(t *testing.T){ do(32, r("A",31), r("\x01", 1), t)}
func Test32x032(t *testing.T){ do(32, r("A",32), r("\x00",32), t)}
func Test32x033(t *testing.T){ do(32, r("A",33), r("\x1f",31), t)}
func Test32x034(t *testing.T){ do(32, r("A",34), r("\x1e",30), t)}
func Test32x035(t *testing.T){ do(32, r("A",35), r("\x1d",29), t)}
func Test32x036(t *testing.T){ do(32, r("A",36), r("\x1c",28), t)}
func Test32x037(t *testing.T){ do(32, r("A",37), r("\x1b",27), t)}
func Test32x038(t *testing.T){ do(32, r("A",38), r("\x1a",26), t)}
func Test32x039(t *testing.T){ do(32, r("A",39), r("\x19",25), t)}
func Test32x040(t *testing.T){ do(32, r("A",40), r("\x18",24), t)}
func Test32x041(t *testing.T){ do(32, r("A",41), r("\x17",23), t)}
func Test32x042(t *testing.T){ do(32, r("A",42), r("\x16",22), t)}
func Test32x043(t *testing.T){ do(32, r("A",43), r("\x15",21), t)}
func Test32x044(t *testing.T){ do(32, r("A",44), r("\x14",20), t)}
func Test32x045(t *testing.T){ do(32, r("A",45), r("\x13",19), t)}
func Test32x046(t *testing.T){ do(32, r("A",46), r("\x12",18), t)}
func Test32x047(t *testing.T){ do(32, r("A",47), r("\x11",17), t)}
func Test32x048(t *testing.T){ do(32, r("A",48), r("\x10",16), t)}
func Test32x049(t *testing.T){ do(32, r("A",49), r("\x0f",15), t)}
func Test32x050(t *testing.T){ do(32, r("A",50), r("\x0e",14), t)}
func Test32x051(t *testing.T){ do(32, r("A",51), r("\x0d",13), t)}
func Test32x052(t *testing.T){ do(32, r("A",52), r("\x0c",12), t)}
func Test32x053(t *testing.T){ do(32, r("A",53), r("\x0b",11), t)}
func Test32x054(t *testing.T){ do(32, r("A",54), r("\x0a",10), t)}
func Test32x055(t *testing.T){ do(32, r("A",55), r("\x09", 9), t)}
func Test32x056(t *testing.T){ do(32, r("A",56), r("\x08", 8), t)}
func Test32x057(t *testing.T){ do(32, r("A",57), r("\x07", 7), t)}
func Test32x058(t *testing.T){ do(32, r("A",58), r("\x06", 6), t)}
func Test32x059(t *testing.T){ do(32, r("A",59), r("\x05", 5), t)}
func Test32x060(t *testing.T){ do(32, r("A",60), r("\x04", 4), t)}
func Test32x061(t *testing.T){ do(32, r("A",61), r("\x03", 3), t)}
func Test32x062(t *testing.T){ do(32, r("A",62), r("\x02", 2), t)}
func Test32x063(t *testing.T){ do(32, r("A",63), r("\x01", 1), t)}
func Test32x064(t *testing.T){ do(32, r("A",64), r("\x00",32), t)}
func Test32x065(t *testing.T){ do(32, r("A",65), r("\x1f",31), t)}
func Test32x066(t *testing.T){ do(32, r("A",66), r("\x1e",30), t)}
func Test32x067(t *testing.T){ do(32, r("A",67), r("\x1d",29), t)}
func Test32x068(t *testing.T){ do(32, r("A",68), r("\x1c",28), t)}
func Test32x069(t *testing.T){ do(32, r("A",69), r("\x1b",27), t)}
func Test32x070(t *testing.T){ do(32, r("A",70), r("\x1a",26), t)}
func Test32x071(t *testing.T){ do(32, r("A",71), r("\x19",25), t)}
func Test32x072(t *testing.T){ do(32, r("A",72), r("\x18",24), t)}
func Test32x073(t *testing.T){ do(32, r("A",73), r("\x17",23), t)}
func Test32x074(t *testing.T){ do(32, r("A",74), r("\x16",22), t)}
func Test32x075(t *testing.T){ do(32, r("A",75), r("\x15",21), t)}
func Test32x076(t *testing.T){ do(32, r("A",76), r("\x14",20), t)}
func Test32x077(t *testing.T){ do(32, r("A",77), r("\x13",19), t)}
func Test32x078(t *testing.T){ do(32, r("A",78), r("\x12",18), t)}
func Test32x079(t *testing.T){ do(32, r("A",79), r("\x11",17), t)}
func Test32x080(t *testing.T){ do(32, r("A",80), r("\x10",16), t)}
func Test32x081(t *testing.T){ do(32, r("A",81), r("\x0f",15), t)}
func Test32x082(t *testing.T){ do(32, r("A",82), r("\x0e",14), t)}
func Test32x083(t *testing.T){ do(32, r("A",83), r("\x0d",13), t)}
func Test32x084(t *testing.T){ do(32, r("A",84), r("\x0c",12), t)}
func Test32x085(t *testing.T){ do(32, r("A",85), r("\x0b",11), t)}
func Test32x086(t *testing.T){ do(32, r("A",86), r("\x0a",10), t)}
func Test32x087(t *testing.T){ do(32, r("A",87), r("\x09", 9), t)}
func Test32x088(t *testing.T){ do(32, r("A",88), r("\x08", 8), t)}
func Test32x089(t *testing.T){ do(32, r("A",89), r("\x07", 7), t)}
func Test32x090(t *testing.T){ do(32, r("A",90), r("\x06", 6), t)}
func Test32x091(t *testing.T){ do(32, r("A",91), r("\x05", 5), t)}
func Test32x092(t *testing.T){ do(32, r("A",92), r("\x04", 4), t)}
func Test32x093(t *testing.T){ do(32, r("A",93), r("\x03", 3), t)}
func Test32x094(t *testing.T){ do(32, r("A",94), r("\x02", 2), t)}
func Test32x095(t *testing.T){ do(32, r("A",95), r("\x01", 1), t)}
func Test32x096(t *testing.T){ do(32, r("A",96), r("\x00",32), t)}
func Test32x097(t *testing.T){ do(32, r("A",97), r("\x1f",31), t)}
func Test32x098(t *testing.T){ do(32, r("A",98), r("\x1e",30), t)}
func Test32x099(t *testing.T){ do(32, r("A",99), r("\x1d",29), t)}
func Test32x100(t *testing.T){ do(32, r("A",100), r("\x1c",28), t)}
func Test32x101(t *testing.T){ do(32, r("A",101), r("\x1b",27), t)}
func Test32x102(t *testing.T){ do(32, r("A",102), r("\x1a",26), t)}
func Test32x103(t *testing.T){ do(32, r("A",103), r("\x19",25), t)}
func Test32x104(t *testing.T){ do(32, r("A",104), r("\x18",24), t)}
func Test32x105(t *testing.T){ do(32, r("A",105), r("\x17",23), t)}
func Test32x106(t *testing.T){ do(32, r("A",106), r("\x16",22), t)}
func Test32x107(t *testing.T){ do(32, r("A",107), r("\x15",21), t)}
func Test32x108(t *testing.T){ do(32, r("A",108), r("\x14",20), t)}
func Test32x109(t *testing.T){ do(32, r("A",109), r("\x13",19), t)}
func Test32x110(t *testing.T){ do(32, r("A",110), r("\x12",18), t)}
func Test32x111(t *testing.T){ do(32, r("A",111), r("\x11",17), t)}
func Test32x112(t *testing.T){ do(32, r("A",112), r("\x10",16), t)}
func Test32x113(t *testing.T){ do(32, r("A",113), r("\x0f",15), t)}
func Test32x114(t *testing.T){ do(32, r("A",114), r("\x0e",14), t)}
func Test32x115(t *testing.T){ do(32, r("A",115), r("\x0d",13), t)}
func Test32x116(t *testing.T){ do(32, r("A",116), r("\x0c",12), t)}
func Test32x117(t *testing.T){ do(32, r("A",117), r("\x0b",11), t)}
func Test32x118(t *testing.T){ do(32, r("A",118), r("\x0a",10), t)}
func Test32x119(t *testing.T){ do(32, r("A",119), r("\x09", 9), t)}
func Test32x120(t *testing.T){ do(32, r("A",120), r("\x08", 8), t)}
func Test32x121(t *testing.T){ do(32, r("A",121), r("\x07", 7), t)}
func Test32x122(t *testing.T){ do(32, r("A",122), r("\x06", 6), t)}
func Test32x123(t *testing.T){ do(32, r("A",123), r("\x05", 5), t)}
func Test32x124(t *testing.T){ do(32, r("A",124), r("\x04", 4), t)}
func Test32x125(t *testing.T){ do(32, r("A",125), r("\x03", 3), t)}
func Test32x126(t *testing.T){ do(32, r("A",126), r("\x02", 2), t)}
func Test32x127(t *testing.T){ do(32, r("A",127), r("\x01", 1), t)}
func Test32x128(t *testing.T){ do(32, r("A",128), r("\x00",32), t)}
func Test32x129(t *testing.T){ do(32, r("A",129), r("\x1f",31), t)}
func Test32x130(t *testing.T){ do(32, r("A",130), r("\x1e",30), t)}
func Test32x131(t *testing.T){ do(32, r("A",131), r("\x1d",29), t)}
func Test32x132(t *testing.T){ do(32, r("A",132), r("\x1c",28), t)}
func Test32x133(t *testing.T){ do(32, r("A",133), r("\x1b",27), t)}
func Test32x134(t *testing.T){ do(32, r("A",134), r("\x1a",26), t)}
func Test32x135(t *testing.T){ do(32, r("A",135), r("\x19",25), t)}
func Test32x136(t *testing.T){ do(32, r("A",136), r("\x18",24), t)}
func Test32x137(t *testing.T){ do(32, r("A",137), r("\x17",23), t)}
func Test32x138(t *testing.T){ do(32, r("A",138), r("\x16",22), t)}
func Test32x139(t *testing.T){ do(32, r("A",139), r("\x15",21), t)}
func Test32x140(t *testing.T){ do(32, r("A",140), r("\x14",20), t)}
func Test32x141(t *testing.T){ do(32, r("A",141), r("\x13",19), t)}
func Test32x142(t *testing.T){ do(32, r("A",142), r("\x12",18), t)}
func Test32x143(t *testing.T){ do(32, r("A",143), r("\x11",17), t)}
func Test32x144(t *testing.T){ do(32, r("A",144), r("\x10",16), t)}
func Test32x145(t *testing.T){ do(32, r("A",145), r("\x0f",15), t)}
func Test32x146(t *testing.T){ do(32, r("A",146), r("\x0e",14), t)}
func Test32x147(t *testing.T){ do(32, r("A",147), r("\x0d",13), t)}
func Test32x148(t *testing.T){ do(32, r("A",148), r("\x0c",12), t)}
func Test32x149(t *testing.T){ do(32, r("A",149), r("\x0b",11), t)}
func Test32x150(t *testing.T){ do(32, r("A",150), r("\x0a",10), t)}
func Test32x151(t *testing.T){ do(32, r("A",151), r("\x09", 9), t)}
func Test32x152(t *testing.T){ do(32, r("A",152), r("\x08", 8), t)}
func Test32x153(t *testing.T){ do(32, r("A",153), r("\x07", 7), t)}
func Test32x154(t *testing.T){ do(32, r("A",154), r("\x06", 6), t)}
func Test32x155(t *testing.T){ do(32, r("A",155), r("\x05", 5), t)}
func Test32x156(t *testing.T){ do(32, r("A",156), r("\x04", 4), t)}
func Test32x157(t *testing.T){ do(32, r("A",157), r("\x03", 3), t)}
func Test32x158(t *testing.T){ do(32, r("A",158), r("\x02", 2), t)}
func Test32x159(t *testing.T){ do(32, r("A",159), r("\x01", 1), t)}
func Test32x160(t *testing.T){ do(32, r("A",160), r("\x00",32), t)}
func Test32x161(t *testing.T){ do(32, r("A",161), r("\x1f",31), t)}
func Test32x162(t *testing.T){ do(32, r("A",162), r("\x1e",30), t)}
func Test32x163(t *testing.T){ do(32, r("A",163), r("\x1d",29), t)}
func Test32x164(t *testing.T){ do(32, r("A",164), r("\x1c",28), t)}
func Test32x165(t *testing.T){ do(32, r("A",165), r("\x1b",27), t)}
func Test32x166(t *testing.T){ do(32, r("A",166), r("\x1a",26), t)}
func Test32x167(t *testing.T){ do(32, r("A",167), r("\x19",25), t)}
func Test32x168(t *testing.T){ do(32, r("A",168), r("\x18",24), t)}
func Test32x169(t *testing.T){ do(32, r("A",169), r("\x17",23), t)}
func Test32x170(t *testing.T){ do(32, r("A",170), r("\x16",22), t)}
func Test32x171(t *testing.T){ do(32, r("A",171), r("\x15",21), t)}
func Test32x172(t *testing.T){ do(32, r("A",172), r("\x14",20), t)}
func Test32x173(t *testing.T){ do(32, r("A",173), r("\x13",19), t)}
func Test32x174(t *testing.T){ do(32, r("A",174), r("\x12",18), t)}
func Test32x175(t *testing.T){ do(32, r("A",175), r("\x11",17), t)}
func Test32x176(t *testing.T){ do(32, r("A",176), r("\x10",16), t)}
func Test32x177(t *testing.T){ do(32, r("A",177), r("\x0f",15), t)}
func Test32x178(t *testing.T){ do(32, r("A",178), r("\x0e",14), t)}
func Test32x179(t *testing.T){ do(32, r("A",179), r("\x0d",13), t)}
func Test32x180(t *testing.T){ do(32, r("A",180), r("\x0c",12), t)}
func Test32x181(t *testing.T){ do(32, r("A",181), r("\x0b",11), t)}
func Test32x182(t *testing.T){ do(32, r("A",182), r("\x0a",10), t)}
func Test32x183(t *testing.T){ do(32, r("A",183), r("\x09", 9), t)}
func Test32x184(t *testing.T){ do(32, r("A",184), r("\x08", 8), t)}
func Test32x185(t *testing.T){ do(32, r("A",185), r("\x07", 7), t)}
func Test32x186(t *testing.T){ do(32, r("A",186), r("\x06", 6), t)}
func Test32x187(t *testing.T){ do(32, r("A",187), r("\x05", 5), t)}
func Test32x188(t *testing.T){ do(32, r("A",188), r("\x04", 4), t)}
func Test32x189(t *testing.T){ do(32, r("A",189), r("\x03", 3), t)}
func Test32x190(t *testing.T){ do(32, r("A",190), r("\x02", 2), t)}
func Test32x191(t *testing.T){ do(32, r("A",191), r("\x01", 1), t)}
func Test32x192(t *testing.T){ do(32, r("A",192), r("\x00",32), t)}
func Test32x193(t *testing.T){ do(32, r("A",193), r("\x1f",31), t)}
func Test32x194(t *testing.T){ do(32, r("A",194), r("\x1e",30), t)}
func Test32x195(t *testing.T){ do(32, r("A",195), r("\x1d",29), t)}
func Test32x196(t *testing.T){ do(32, r("A",196), r("\x1c",28), t)}
func Test32x197(t *testing.T){ do(32, r("A",197), r("\x1b",27), t)}
func Test32x198(t *testing.T){ do(32, r("A",198), r("\x1a",26), t)}
func Test32x199(t *testing.T){ do(32, r("A",199), r("\x19",25), t)}
func Test32x200(t *testing.T){ do(32, r("A",200), r("\x18",24), t)}
func Test32x201(t *testing.T){ do(32, r("A",201), r("\x17",23), t)}
func Test32x202(t *testing.T){ do(32, r("A",202), r("\x16",22), t)}
func Test32x203(t *testing.T){ do(32, r("A",203), r("\x15",21), t)}
func Test32x204(t *testing.T){ do(32, r("A",204), r("\x14",20), t)}
func Test32x205(t *testing.T){ do(32, r("A",205), r("\x13",19), t)}
func Test32x206(t *testing.T){ do(32, r("A",206), r("\x12",18), t)}
func Test32x207(t *testing.T){ do(32, r("A",207), r("\x11",17), t)}
func Test32x208(t *testing.T){ do(32, r("A",208), r("\x10",16), t)}
func Test32x209(t *testing.T){ do(32, r("A",209), r("\x0f",15), t)}
func Test32x210(t *testing.T){ do(32, r("A",210), r("\x0e",14), t)}
func Test32x211(t *testing.T){ do(32, r("A",211), r("\x0d",13), t)}
func Test32x212(t *testing.T){ do(32, r("A",212), r("\x0c",12), t)}
func Test32x213(t *testing.T){ do(32, r("A",213), r("\x0b",11), t)}
func Test32x214(t *testing.T){ do(32, r("A",214), r("\x0a",10), t)}
func Test32x215(t *testing.T){ do(32, r("A",215), r("\x09", 9), t)}
func Test32x216(t *testing.T){ do(32, r("A",216), r("\x08", 8), t)}
func Test32x217(t *testing.T){ do(32, r("A",217), r("\x07", 7), t)}
func Test32x218(t *testing.T){ do(32, r("A",218), r("\x06", 6), t)}
func Test32x219(t *testing.T){ do(32, r("A",219), r("\x05", 5), t)}
func Test32x220(t *testing.T){ do(32, r("A",220), r("\x04", 4), t)}
func Test32x221(t *testing.T){ do(32, r("A",221), r("\x03", 3), t)}
func Test32x222(t *testing.T){ do(32, r("A",222), r("\x02", 2), t)}
func Test32x223(t *testing.T){ do(32, r("A",223), r("\x01", 1), t)}
func Test32x224(t *testing.T){ do(32, r("A",224), r("\x00",32), t)}
func Test32x225(t *testing.T){ do(32, r("A",225), r("\x1f",31), t)}
func Test32x226(t *testing.T){ do(32, r("A",226), r("\x1e",30), t)}
func Test32x227(t *testing.T){ do(32, r("A",227), r("\x1d",29), t)}
func Test32x228(t *testing.T){ do(32, r("A",228), r("\x1c",28), t)}
func Test32x229(t *testing.T){ do(32, r("A",229), r("\x1b",27), t)}
func Test32x230(t *testing.T){ do(32, r("A",230), r("\x1a",26), t)}
func Test32x231(t *testing.T){ do(32, r("A",231), r("\x19",25), t)}
func Test32x232(t *testing.T){ do(32, r("A",232), r("\x18",24), t)}
func Test32x233(t *testing.T){ do(32, r("A",233), r("\x17",23), t)}
func Test32x234(t *testing.T){ do(32, r("A",234), r("\x16",22), t)}
func Test32x235(t *testing.T){ do(32, r("A",235), r("\x15",21), t)}
func Test32x236(t *testing.T){ do(32, r("A",236), r("\x14",20), t)}
func Test32x237(t *testing.T){ do(32, r("A",237), r("\x13",19), t)}
func Test32x238(t *testing.T){ do(32, r("A",238), r("\x12",18), t)}
func Test32x239(t *testing.T){ do(32, r("A",239), r("\x11",17), t)}
func Test32x240(t *testing.T){ do(32, r("A",240), r("\x10",16), t)}
func Test32x241(t *testing.T){ do(32, r("A",241), r("\x0f",15), t)}
func Test32x242(t *testing.T){ do(32, r("A",242), r("\x0e",14), t)}
func Test32x243(t *testing.T){ do(32, r("A",243), r("\x0d",13), t)}
func Test32x244(t *testing.T){ do(32, r("A",244), r("\x0c",12), t)}
func Test32x245(t *testing.T){ do(32, r("A",245), r("\x0b",11), t)}
func Test32x246(t *testing.T){ do(32, r("A",246), r("\x0a",10), t)}
func Test32x247(t *testing.T){ do(32, r("A",247), r("\x09", 9), t)}
func Test32x248(t *testing.T){ do(32, r("A",248), r("\x08", 8), t)}
func Test32x249(t *testing.T){ do(32, r("A",249), r("\x07", 7), t)}
func Test32x250(t *testing.T){ do(32, r("A",250), r("\x06", 6), t)}
func Test32x251(t *testing.T){ do(32, r("A",251), r("\x05", 5), t)}
func Test32x252(t *testing.T){ do(32, r("A",252), r("\x04", 4), t)}
func Test32x253(t *testing.T){ do(32, r("A",253), r("\x03", 3), t)}
func Test32x254(t *testing.T){ do(32, r("A",254), r("\x02", 2), t)}
func Test32x255(t *testing.T){ do(32, r("A",255), r("\x01", 1), t)}
func Test64x000(t *testing.T){ do(64, r("A", 0), r("\x00",64), t)}
func Test64x001(t *testing.T){ do(64, r("A", 1), r("\x3f",63), t)}
func Test64x002(t *testing.T){ do(64, r("A", 2), r("\x3e",62), t)}
func Test64x003(t *testing.T){ do(64, r("A", 3), r("\x3d",61), t)}
func Test64x004(t *testing.T){ do(64, r("A", 4), r("\x3c",60), t)}
func Test64x005(t *testing.T){ do(64, r("A", 5), r("\x3b",59), t)}
func Test64x006(t *testing.T){ do(64, r("A", 6), r("\x3a",58), t)}
func Test64x007(t *testing.T){ do(64, r("A", 7), r("\x39",57), t)}
func Test64x008(t *testing.T){ do(64, r("A", 8), r("\x38",56), t)}
func Test64x009(t *testing.T){ do(64, r("A", 9), r("\x37",55), t)}
func Test64x010(t *testing.T){ do(64, r("A",10), r("\x36",54), t)}
func Test64x011(t *testing.T){ do(64, r("A",11), r("\x35",53), t)}
func Test64x012(t *testing.T){ do(64, r("A",12), r("\x34",52), t)}
func Test64x013(t *testing.T){ do(64, r("A",13), r("\x33",51), t)}
func Test64x014(t *testing.T){ do(64, r("A",14), r("\x32",50), t)}
func Test64x015(t *testing.T){ do(64, r("A",15), r("\x31",49), t)}
func Test64x016(t *testing.T){ do(64, r("A",16), r("\x30",48), t)}
func Test64x017(t *testing.T){ do(64, r("A",17), r("\x2f",47), t)}
func Test64x018(t *testing.T){ do(64, r("A",18), r("\x2e",46), t)}
func Test64x019(t *testing.T){ do(64, r("A",19), r("\x2d",45), t)}
func Test64x020(t *testing.T){ do(64, r("A",20), r("\x2c",44), t)}
func Test64x021(t *testing.T){ do(64, r("A",21), r("\x2b",43), t)}
func Test64x022(t *testing.T){ do(64, r("A",22), r("\x2a",42), t)}
func Test64x023(t *testing.T){ do(64, r("A",23), r("\x29",41), t)}
func Test64x024(t *testing.T){ do(64, r("A",24), r("\x28",40), t)}
func Test64x025(t *testing.T){ do(64, r("A",25), r("\x27",39), t)}
func Test64x026(t *testing.T){ do(64, r("A",26), r("\x26",38), t)}
func Test64x027(t *testing.T){ do(64, r("A",27), r("\x25",37), t)}
func Test64x028(t *testing.T){ do(64, r("A",28), r("\x24",36), t)}
func Test64x029(t *testing.T){ do(64, r("A",29), r("\x23",35), t)}
func Test64x030(t *testing.T){ do(64, r("A",30), r("\x22",34), t)}
func Test64x031(t *testing.T){ do(64, r("A",31), r("\x21",33), t)}
func Test64x032(t *testing.T){ do(64, r("A",32), r("\x20",32), t)}
func Test64x033(t *testing.T){ do(64, r("A",33), r("\x1f",31), t)}
func Test64x034(t *testing.T){ do(64, r("A",34), r("\x1e",30), t)}
func Test64x035(t *testing.T){ do(64, r("A",35), r("\x1d",29), t)}
func Test64x036(t *testing.T){ do(64, r("A",36), r("\x1c",28), t)}
func Test64x037(t *testing.T){ do(64, r("A",37), r("\x1b",27), t)}
func Test64x038(t *testing.T){ do(64, r("A",38), r("\x1a",26), t)}
func Test64x039(t *testing.T){ do(64, r("A",39), r("\x19",25), t)}
func Test64x040(t *testing.T){ do(64, r("A",40), r("\x18",24), t)}
func Test64x041(t *testing.T){ do(64, r("A",41), r("\x17",23), t)}
func Test64x042(t *testing.T){ do(64, r("A",42), r("\x16",22), t)}
func Test64x043(t *testing.T){ do(64, r("A",43), r("\x15",21), t)}
func Test64x044(t *testing.T){ do(64, r("A",44), r("\x14",20), t)}
func Test64x045(t *testing.T){ do(64, r("A",45), r("\x13",19), t)}
func Test64x046(t *testing.T){ do(64, r("A",46), r("\x12",18), t)}
func Test64x047(t *testing.T){ do(64, r("A",47), r("\x11",17), t)}
func Test64x048(t *testing.T){ do(64, r("A",48), r("\x10",16), t)}
func Test64x049(t *testing.T){ do(64, r("A",49), r("\x0f",15), t)}
func Test64x050(t *testing.T){ do(64, r("A",50), r("\x0e",14), t)}
func Test64x051(t *testing.T){ do(64, r("A",51), r("\x0d",13), t)}
func Test64x052(t *testing.T){ do(64, r("A",52), r("\x0c",12), t)}
func Test64x053(t *testing.T){ do(64, r("A",53), r("\x0b",11), t)}
func Test64x054(t *testing.T){ do(64, r("A",54), r("\x0a",10), t)}
func Test64x055(t *testing.T){ do(64, r("A",55), r("\x09", 9), t)}
func Test64x056(t *testing.T){ do(64, r("A",56), r("\x08", 8), t)}
func Test64x057(t *testing.T){ do(64, r("A",57), r("\x07", 7), t)}
func Test64x058(t *testing.T){ do(64, r("A",58), r("\x06", 6), t)}
func Test64x059(t *testing.T){ do(64, r("A",59), r("\x05", 5), t)}
func Test64x060(t *testing.T){ do(64, r("A",60), r("\x04", 4), t)}
func Test64x061(t *testing.T){ do(64, r("A",61), r("\x03", 3), t)}
func Test64x062(t *testing.T){ do(64, r("A",62), r("\x02", 2), t)}
func Test64x063(t *testing.T){ do(64, r("A",63), r("\x01", 1), t)}
func Test64x064(t *testing.T){ do(64, r("A",64), r("\x00",64), t)}
func Test64x065(t *testing.T){ do(64, r("A",65), r("\x3f",63), t)}
func Test64x066(t *testing.T){ do(64, r("A",66), r("\x3e",62), t)}
func Test64x067(t *testing.T){ do(64, r("A",67), r("\x3d",61), t)}
func Test64x068(t *testing.T){ do(64, r("A",68), r("\x3c",60), t)}
func Test64x069(t *testing.T){ do(64, r("A",69), r("\x3b",59), t)}
func Test64x070(t *testing.T){ do(64, r("A",70), r("\x3a",58), t)}
func Test64x071(t *testing.T){ do(64, r("A",71), r("\x39",57), t)}
func Test64x072(t *testing.T){ do(64, r("A",72), r("\x38",56), t)}
func Test64x073(t *testing.T){ do(64, r("A",73), r("\x37",55), t)}
func Test64x074(t *testing.T){ do(64, r("A",74), r("\x36",54), t)}
func Test64x075(t *testing.T){ do(64, r("A",75), r("\x35",53), t)}
func Test64x076(t *testing.T){ do(64, r("A",76), r("\x34",52), t)}
func Test64x077(t *testing.T){ do(64, r("A",77), r("\x33",51), t)}
func Test64x078(t *testing.T){ do(64, r("A",78), r("\x32",50), t)}
func Test64x079(t *testing.T){ do(64, r("A",79), r("\x31",49), t)}
func Test64x080(t *testing.T){ do(64, r("A",80), r("\x30",48), t)}
func Test64x081(t *testing.T){ do(64, r("A",81), r("\x2f",47), t)}
func Test64x082(t *testing.T){ do(64, r("A",82), r("\x2e",46), t)}
func Test64x083(t *testing.T){ do(64, r("A",83), r("\x2d",45), t)}
func Test64x084(t *testing.T){ do(64, r("A",84), r("\x2c",44), t)}
func Test64x085(t *testing.T){ do(64, r("A",85), r("\x2b",43), t)}
func Test64x086(t *testing.T){ do(64, r("A",86), r("\x2a",42), t)}
func Test64x087(t *testing.T){ do(64, r("A",87), r("\x29",41), t)}
func Test64x088(t *testing.T){ do(64, r("A",88), r("\x28",40), t)}
func Test64x089(t *testing.T){ do(64, r("A",89), r("\x27",39), t)}
func Test64x090(t *testing.T){ do(64, r("A",90), r("\x26",38), t)}
func Test64x091(t *testing.T){ do(64, r("A",91), r("\x25",37), t)}
func Test64x092(t *testing.T){ do(64, r("A",92), r("\x24",36), t)}
func Test64x093(t *testing.T){ do(64, r("A",93), r("\x23",35), t)}
func Test64x094(t *testing.T){ do(64, r("A",94), r("\x22",34), t)}
func Test64x095(t *testing.T){ do(64, r("A",95), r("\x21",33), t)}
func Test64x096(t *testing.T){ do(64, r("A",96), r("\x20",32), t)}
func Test64x097(t *testing.T){ do(64, r("A",97), r("\x1f",31), t)}
func Test64x098(t *testing.T){ do(64, r("A",98), r("\x1e",30), t)}
func Test64x099(t *testing.T){ do(64, r("A",99), r("\x1d",29), t)}
func Test64x100(t *testing.T){ do(64, r("A",100), r("\x1c",28), t)}
func Test64x101(t *testing.T){ do(64, r("A",101), r("\x1b",27), t)}
func Test64x102(t *testing.T){ do(64, r("A",102), r("\x1a",26), t)}
func Test64x103(t *testing.T){ do(64, r("A",103), r("\x19",25), t)}
func Test64x104(t *testing.T){ do(64, r("A",104), r("\x18",24), t)}
func Test64x105(t *testing.T){ do(64, r("A",105), r("\x17",23), t)}
func Test64x106(t *testing.T){ do(64, r("A",106), r("\x16",22), t)}
func Test64x107(t *testing.T){ do(64, r("A",107), r("\x15",21), t)}
func Test64x108(t *testing.T){ do(64, r("A",108), r("\x14",20), t)}
func Test64x109(t *testing.T){ do(64, r("A",109), r("\x13",19), t)}
func Test64x110(t *testing.T){ do(64, r("A",110), r("\x12",18), t)}
func Test64x111(t *testing.T){ do(64, r("A",111), r("\x11",17), t)}
func Test64x112(t *testing.T){ do(64, r("A",112), r("\x10",16), t)}
func Test64x113(t *testing.T){ do(64, r("A",113), r("\x0f",15), t)}
func Test64x114(t *testing.T){ do(64, r("A",114), r("\x0e",14), t)}
func Test64x115(t *testing.T){ do(64, r("A",115), r("\x0d",13), t)}
func Test64x116(t *testing.T){ do(64, r("A",116), r("\x0c",12), t)}
func Test64x117(t *testing.T){ do(64, r("A",117), r("\x0b",11), t)}
func Test64x118(t *testing.T){ do(64, r("A",118), r("\x0a",10), t)}
func Test64x119(t *testing.T){ do(64, r("A",119), r("\x09", 9), t)}
func Test64x120(t *testing.T){ do(64, r("A",120), r("\x08", 8), t)}
func Test64x121(t *testing.T){ do(64, r("A",121), r("\x07", 7), t)}
func Test64x122(t *testing.T){ do(64, r("A",122), r("\x06", 6), t)}
func Test64x123(t *testing.T){ do(64, r("A",123), r("\x05", 5), t)}
func Test64x124(t *testing.T){ do(64, r("A",124), r("\x04", 4), t)}
func Test64x125(t *testing.T){ do(64, r("A",125), r("\x03", 3), t)}
func Test64x126(t *testing.T){ do(64, r("A",126), r("\x02", 2), t)}
func Test64x127(t *testing.T){ do(64, r("A",127), r("\x01", 1), t)}
func Test64x128(t *testing.T){ do(64, r("A",128), r("\x00",64), t)}
func Test64x129(t *testing.T){ do(64, r("A",129), r("\x3f",63), t)}
func Test64x130(t *testing.T){ do(64, r("A",130), r("\x3e",62), t)}
func Test64x131(t *testing.T){ do(64, r("A",131), r("\x3d",61), t)}
func Test64x132(t *testing.T){ do(64, r("A",132), r("\x3c",60), t)}
func Test64x133(t *testing.T){ do(64, r("A",133), r("\x3b",59), t)}
func Test64x134(t *testing.T){ do(64, r("A",134), r("\x3a",58), t)}
func Test64x135(t *testing.T){ do(64, r("A",135), r("\x39",57), t)}
func Test64x136(t *testing.T){ do(64, r("A",136), r("\x38",56), t)}
func Test64x137(t *testing.T){ do(64, r("A",137), r("\x37",55), t)}
func Test64x138(t *testing.T){ do(64, r("A",138), r("\x36",54), t)}
func Test64x139(t *testing.T){ do(64, r("A",139), r("\x35",53), t)}
func Test64x140(t *testing.T){ do(64, r("A",140), r("\x34",52), t)}
func Test64x141(t *testing.T){ do(64, r("A",141), r("\x33",51), t)}
func Test64x142(t *testing.T){ do(64, r("A",142), r("\x32",50), t)}
func Test64x143(t *testing.T){ do(64, r("A",143), r("\x31",49), t)}
func Test64x144(t *testing.T){ do(64, r("A",144), r("\x30",48), t)}
func Test64x145(t *testing.T){ do(64, r("A",145), r("\x2f",47), t)}
func Test64x146(t *testing.T){ do(64, r("A",146), r("\x2e",46), t)}
func Test64x147(t *testing.T){ do(64, r("A",147), r("\x2d",45), t)}
func Test64x148(t *testing.T){ do(64, r("A",148), r("\x2c",44), t)}
func Test64x149(t *testing.T){ do(64, r("A",149), r("\x2b",43), t)}
func Test64x150(t *testing.T){ do(64, r("A",150), r("\x2a",42), t)}
func Test64x151(t *testing.T){ do(64, r("A",151), r("\x29",41), t)}
func Test64x152(t *testing.T){ do(64, r("A",152), r("\x28",40), t)}
func Test64x153(t *testing.T){ do(64, r("A",153), r("\x27",39), t)}
func Test64x154(t *testing.T){ do(64, r("A",154), r("\x26",38), t)}
func Test64x155(t *testing.T){ do(64, r("A",155), r("\x25",37), t)}
func Test64x156(t *testing.T){ do(64, r("A",156), r("\x24",36), t)}
func Test64x157(t *testing.T){ do(64, r("A",157), r("\x23",35), t)}
func Test64x158(t *testing.T){ do(64, r("A",158), r("\x22",34), t)}
func Test64x159(t *testing.T){ do(64, r("A",159), r("\x21",33), t)}
func Test64x160(t *testing.T){ do(64, r("A",160), r("\x20",32), t)}
func Test64x161(t *testing.T){ do(64, r("A",161), r("\x1f",31), t)}
func Test64x162(t *testing.T){ do(64, r("A",162), r("\x1e",30), t)}
func Test64x163(t *testing.T){ do(64, r("A",163), r("\x1d",29), t)}
func Test64x164(t *testing.T){ do(64, r("A",164), r("\x1c",28), t)}
func Test64x165(t *testing.T){ do(64, r("A",165), r("\x1b",27), t)}
func Test64x166(t *testing.T){ do(64, r("A",166), r("\x1a",26), t)}
func Test64x167(t *testing.T){ do(64, r("A",167), r("\x19",25), t)}
func Test64x168(t *testing.T){ do(64, r("A",168), r("\x18",24), t)}
func Test64x169(t *testing.T){ do(64, r("A",169), r("\x17",23), t)}
func Test64x170(t *testing.T){ do(64, r("A",170), r("\x16",22), t)}
func Test64x171(t *testing.T){ do(64, r("A",171), r("\x15",21), t)}
func Test64x172(t *testing.T){ do(64, r("A",172), r("\x14",20), t)}
func Test64x173(t *testing.T){ do(64, r("A",173), r("\x13",19), t)}
func Test64x174(t *testing.T){ do(64, r("A",174), r("\x12",18), t)}
func Test64x175(t *testing.T){ do(64, r("A",175), r("\x11",17), t)}
func Test64x176(t *testing.T){ do(64, r("A",176), r("\x10",16), t)}
func Test64x177(t *testing.T){ do(64, r("A",177), r("\x0f",15), t)}
func Test64x178(t *testing.T){ do(64, r("A",178), r("\x0e",14), t)}
func Test64x179(t *testing.T){ do(64, r("A",179), r("\x0d",13), t)}
func Test64x180(t *testing.T){ do(64, r("A",180), r("\x0c",12), t)}
func Test64x181(t *testing.T){ do(64, r("A",181), r("\x0b",11), t)}
func Test64x182(t *testing.T){ do(64, r("A",182), r("\x0a",10), t)}
func Test64x183(t *testing.T){ do(64, r("A",183), r("\x09", 9), t)}
func Test64x184(t *testing.T){ do(64, r("A",184), r("\x08", 8), t)}
func Test64x185(t *testing.T){ do(64, r("A",185), r("\x07", 7), t)}
func Test64x186(t *testing.T){ do(64, r("A",186), r("\x06", 6), t)}
func Test64x187(t *testing.T){ do(64, r("A",187), r("\x05", 5), t)}
func Test64x188(t *testing.T){ do(64, r("A",188), r("\x04", 4), t)}
func Test64x189(t *testing.T){ do(64, r("A",189), r("\x03", 3), t)}
func Test64x190(t *testing.T){ do(64, r("A",190), r("\x02", 2), t)}
func Test64x191(t *testing.T){ do(64, r("A",191), r("\x01", 1), t)}
func Test64x192(t *testing.T){ do(64, r("A",192), r("\x00",64), t)}
func Test64x193(t *testing.T){ do(64, r("A",193), r("\x3f",63), t)}
func Test64x194(t *testing.T){ do(64, r("A",194), r("\x3e",62), t)}
func Test64x195(t *testing.T){ do(64, r("A",195), r("\x3d",61), t)}
func Test64x196(t *testing.T){ do(64, r("A",196), r("\x3c",60), t)}
func Test64x197(t *testing.T){ do(64, r("A",197), r("\x3b",59), t)}
func Test64x198(t *testing.T){ do(64, r("A",198), r("\x3a",58), t)}
func Test64x199(t *testing.T){ do(64, r("A",199), r("\x39",57), t)}
func Test64x200(t *testing.T){ do(64, r("A",200), r("\x38",56), t)}
func Test64x201(t *testing.T){ do(64, r("A",201), r("\x37",55), t)}
func Test64x202(t *testing.T){ do(64, r("A",202), r("\x36",54), t)}
func Test64x203(t *testing.T){ do(64, r("A",203), r("\x35",53), t)}
func Test64x204(t *testing.T){ do(64, r("A",204), r("\x34",52), t)}
func Test64x205(t *testing.T){ do(64, r("A",205), r("\x33",51), t)}
func Test64x206(t *testing.T){ do(64, r("A",206), r("\x32",50), t)}
func Test64x207(t *testing.T){ do(64, r("A",207), r("\x31",49), t)}
func Test64x208(t *testing.T){ do(64, r("A",208), r("\x30",48), t)}
func Test64x209(t *testing.T){ do(64, r("A",209), r("\x2f",47), t)}
func Test64x210(t *testing.T){ do(64, r("A",210), r("\x2e",46), t)}
func Test64x211(t *testing.T){ do(64, r("A",211), r("\x2d",45), t)}
func Test64x212(t *testing.T){ do(64, r("A",212), r("\x2c",44), t)}
func Test64x213(t *testing.T){ do(64, r("A",213), r("\x2b",43), t)}
func Test64x214(t *testing.T){ do(64, r("A",214), r("\x2a",42), t)}
func Test64x215(t *testing.T){ do(64, r("A",215), r("\x29",41), t)}
func Test64x216(t *testing.T){ do(64, r("A",216), r("\x28",40), t)}
func Test64x217(t *testing.T){ do(64, r("A",217), r("\x27",39), t)}
func Test64x218(t *testing.T){ do(64, r("A",218), r("\x26",38), t)}
func Test64x219(t *testing.T){ do(64, r("A",219), r("\x25",37), t)}
func Test64x220(t *testing.T){ do(64, r("A",220), r("\x24",36), t)}
func Test64x221(t *testing.T){ do(64, r("A",221), r("\x23",35), t)}
func Test64x222(t *testing.T){ do(64, r("A",222), r("\x22",34), t)}
func Test64x223(t *testing.T){ do(64, r("A",223), r("\x21",33), t)}
func Test64x224(t *testing.T){ do(64, r("A",224), r("\x20",32), t)}
func Test64x225(t *testing.T){ do(64, r("A",225), r("\x1f",31), t)}
func Test64x226(t *testing.T){ do(64, r("A",226), r("\x1e",30), t)}
func Test64x227(t *testing.T){ do(64, r("A",227), r("\x1d",29), t)}
func Test64x228(t *testing.T){ do(64, r("A",228), r("\x1c",28), t)}
func Test64x229(t *testing.T){ do(64, r("A",229), r("\x1b",27), t)}
func Test64x230(t *testing.T){ do(64, r("A",230), r("\x1a",26), t)}
func Test64x231(t *testing.T){ do(64, r("A",231), r("\x19",25), t)}
func Test64x232(t *testing.T){ do(64, r("A",232), r("\x18",24), t)}
func Test64x233(t *testing.T){ do(64, r("A",233), r("\x17",23), t)}
func Test64x234(t *testing.T){ do(64, r("A",234), r("\x16",22), t)}
func Test64x235(t *testing.T){ do(64, r("A",235), r("\x15",21), t)}
func Test64x236(t *testing.T){ do(64, r("A",236), r("\x14",20), t)}
func Test64x237(t *testing.T){ do(64, r("A",237), r("\x13",19), t)}
func Test64x238(t *testing.T){ do(64, r("A",238), r("\x12",18), t)}
func Test64x239(t *testing.T){ do(64, r("A",239), r("\x11",17), t)}
func Test64x240(t *testing.T){ do(64, r("A",240), r("\x10",16), t)}
func Test64x241(t *testing.T){ do(64, r("A",241), r("\x0f",15), t)}
func Test64x242(t *testing.T){ do(64, r("A",242), r("\x0e",14), t)}
func Test64x243(t *testing.T){ do(64, r("A",243), r("\x0d",13), t)}
func Test64x244(t *testing.T){ do(64, r("A",244), r("\x0c",12), t)}
func Test64x245(t *testing.T){ do(64, r("A",245), r("\x0b",11), t)}
func Test64x246(t *testing.T){ do(64, r("A",246), r("\x0a",10), t)}
func Test64x247(t *testing.T){ do(64, r("A",247), r("\x09", 9), t)}
func Test64x248(t *testing.T){ do(64, r("A",248), r("\x08", 8), t)}
func Test64x249(t *testing.T){ do(64, r("A",249), r("\x07", 7), t)}
func Test64x250(t *testing.T){ do(64, r("A",250), r("\x06", 6), t)}
func Test64x251(t *testing.T){ do(64, r("A",251), r("\x05", 5), t)}
func Test64x252(t *testing.T){ do(64, r("A",252), r("\x04", 4), t)}
func Test64x253(t *testing.T){ do(64, r("A",253), r("\x03", 3), t)}
func Test64x254(t *testing.T){ do(64, r("A",254), r("\x02", 2), t)}
func Test64x255(t *testing.T){ do(64, r("A",255), r("\x01", 1), t)}
func Test128x000(t *testing.T){ do(128, r("A", 0), r("\x00",128), t)}
func Test128x001(t *testing.T){ do(128, r("A", 1), r("\x7f",127), t)}
func Test128x002(t *testing.T){ do(128, r("A", 2), r("\x7e",126), t)}
func Test128x003(t *testing.T){ do(128, r("A", 3), r("\x7d",125), t)}
func Test128x004(t *testing.T){ do(128, r("A", 4), r("\x7c",124), t)}
func Test128x005(t *testing.T){ do(128, r("A", 5), r("\x7b",123), t)}
func Test128x006(t *testing.T){ do(128, r("A", 6), r("\x7a",122), t)}
func Test128x007(t *testing.T){ do(128, r("A", 7), r("\x79",121), t)}
func Test128x008(t *testing.T){ do(128, r("A", 8), r("\x78",120), t)}
func Test128x009(t *testing.T){ do(128, r("A", 9), r("\x77",119), t)}
func Test128x010(t *testing.T){ do(128, r("A",10), r("\x76",118), t)}
func Test128x011(t *testing.T){ do(128, r("A",11), r("\x75",117), t)}
func Test128x012(t *testing.T){ do(128, r("A",12), r("\x74",116), t)}
func Test128x013(t *testing.T){ do(128, r("A",13), r("\x73",115), t)}
func Test128x014(t *testing.T){ do(128, r("A",14), r("\x72",114), t)}
func Test128x015(t *testing.T){ do(128, r("A",15), r("\x71",113), t)}
func Test128x016(t *testing.T){ do(128, r("A",16), r("\x70",112), t)}
func Test128x017(t *testing.T){ do(128, r("A",17), r("\x6f",111), t)}
func Test128x018(t *testing.T){ do(128, r("A",18), r("\x6e",110), t)}
func Test128x019(t *testing.T){ do(128, r("A",19), r("\x6d",109), t)}
func Test128x020(t *testing.T){ do(128, r("A",20), r("\x6c",108), t)}
func Test128x021(t *testing.T){ do(128, r("A",21), r("\x6b",107), t)}
func Test128x022(t *testing.T){ do(128, r("A",22), r("\x6a",106), t)}
func Test128x023(t *testing.T){ do(128, r("A",23), r("\x69",105), t)}
func Test128x024(t *testing.T){ do(128, r("A",24), r("\x68",104), t)}
func Test128x025(t *testing.T){ do(128, r("A",25), r("\x67",103), t)}
func Test128x026(t *testing.T){ do(128, r("A",26), r("\x66",102), t)}
func Test128x027(t *testing.T){ do(128, r("A",27), r("\x65",101), t)}
func Test128x028(t *testing.T){ do(128, r("A",28), r("\x64",100), t)}
func Test128x029(t *testing.T){ do(128, r("A",29), r("\x63",99), t)}
func Test128x030(t *testing.T){ do(128, r("A",30), r("\x62",98), t)}
func Test128x031(t *testing.T){ do(128, r("A",31), r("\x61",97), t)}
func Test128x032(t *testing.T){ do(128, r("A",32), r("\x60",96), t)}
func Test128x033(t *testing.T){ do(128, r("A",33), r("\x5f",95), t)}
func Test128x034(t *testing.T){ do(128, r("A",34), r("\x5e",94), t)}
func Test128x035(t *testing.T){ do(128, r("A",35), r("\x5d",93), t)}
func Test128x036(t *testing.T){ do(128, r("A",36), r("\x5c",92), t)}
func Test128x037(t *testing.T){ do(128, r("A",37), r("\x5b",91), t)}
func Test128x038(t *testing.T){ do(128, r("A",38), r("\x5a",90), t)}
func Test128x039(t *testing.T){ do(128, r("A",39), r("\x59",89), t)}
func Test128x040(t *testing.T){ do(128, r("A",40), r("\x58",88), t)}
func Test128x041(t *testing.T){ do(128, r("A",41), r("\x57",87), t)}
func Test128x042(t *testing.T){ do(128, r("A",42), r("\x56",86), t)}
func Test128x043(t *testing.T){ do(128, r("A",43), r("\x55",85), t)}
func Test128x044(t *testing.T){ do(128, r("A",44), r("\x54",84), t)}
func Test128x045(t *testing.T){ do(128, r("A",45), r("\x53",83), t)}
func Test128x046(t *testing.T){ do(128, r("A",46), r("\x52",82), t)}
func Test128x047(t *testing.T){ do(128, r("A",47), r("\x51",81), t)}
func Test128x048(t *testing.T){ do(128, r("A",48), r("\x50",80), t)}
func Test128x049(t *testing.T){ do(128, r("A",49), r("\x4f",79), t)}
func Test128x050(t *testing.T){ do(128, r("A",50), r("\x4e",78), t)}
func Test128x051(t *testing.T){ do(128, r("A",51), r("\x4d",77), t)}
func Test128x052(t *testing.T){ do(128, r("A",52), r("\x4c",76), t)}
func Test128x053(t *testing.T){ do(128, r("A",53), r("\x4b",75), t)}
func Test128x054(t *testing.T){ do(128, r("A",54), r("\x4a",74), t)}
func Test128x055(t *testing.T){ do(128, r("A",55), r("\x49",73), t)}
func Test128x056(t *testing.T){ do(128, r("A",56), r("\x48",72), t)}
func Test128x057(t *testing.T){ do(128, r("A",57), r("\x47",71), t)}
func Test128x058(t *testing.T){ do(128, r("A",58), r("\x46",70), t)}
func Test128x059(t *testing.T){ do(128, r("A",59), r("\x45",69), t)}
func Test128x060(t *testing.T){ do(128, r("A",60), r("\x44",68), t)}
func Test128x061(t *testing.T){ do(128, r("A",61), r("\x43",67), t)}
func Test128x062(t *testing.T){ do(128, r("A",62), r("\x42",66), t)}
func Test128x063(t *testing.T){ do(128, r("A",63), r("\x41",65), t)}
func Test128x064(t *testing.T){ do(128, r("A",64), r("\x40",64), t)}
func Test128x065(t *testing.T){ do(128, r("A",65), r("\x3f",63), t)}
func Test128x066(t *testing.T){ do(128, r("A",66), r("\x3e",62), t)}
func Test128x067(t *testing.T){ do(128, r("A",67), r("\x3d",61), t)}
func Test128x068(t *testing.T){ do(128, r("A",68), r("\x3c",60), t)}
func Test128x069(t *testing.T){ do(128, r("A",69), r("\x3b",59), t)}
func Test128x070(t *testing.T){ do(128, r("A",70), r("\x3a",58), t)}
func Test128x071(t *testing.T){ do(128, r("A",71), r("\x39",57), t)}
func Test128x072(t *testing.T){ do(128, r("A",72), r("\x38",56), t)}
func Test128x073(t *testing.T){ do(128, r("A",73), r("\x37",55), t)}
func Test128x074(t *testing.T){ do(128, r("A",74), r("\x36",54), t)}
func Test128x075(t *testing.T){ do(128, r("A",75), r("\x35",53), t)}
func Test128x076(t *testing.T){ do(128, r("A",76), r("\x34",52), t)}
func Test128x077(t *testing.T){ do(128, r("A",77), r("\x33",51), t)}
func Test128x078(t *testing.T){ do(128, r("A",78), r("\x32",50), t)}
func Test128x079(t *testing.T){ do(128, r("A",79), r("\x31",49), t)}
func Test128x080(t *testing.T){ do(128, r("A",80), r("\x30",48), t)}
func Test128x081(t *testing.T){ do(128, r("A",81), r("\x2f",47), t)}
func Test128x082(t *testing.T){ do(128, r("A",82), r("\x2e",46), t)}
func Test128x083(t *testing.T){ do(128, r("A",83), r("\x2d",45), t)}
func Test128x084(t *testing.T){ do(128, r("A",84), r("\x2c",44), t)}
func Test128x085(t *testing.T){ do(128, r("A",85), r("\x2b",43), t)}
func Test128x086(t *testing.T){ do(128, r("A",86), r("\x2a",42), t)}
func Test128x087(t *testing.T){ do(128, r("A",87), r("\x29",41), t)}
func Test128x088(t *testing.T){ do(128, r("A",88), r("\x28",40), t)}
func Test128x089(t *testing.T){ do(128, r("A",89), r("\x27",39), t)}
func Test128x090(t *testing.T){ do(128, r("A",90), r("\x26",38), t)}
func Test128x091(t *testing.T){ do(128, r("A",91), r("\x25",37), t)}
func Test128x092(t *testing.T){ do(128, r("A",92), r("\x24",36), t)}
func Test128x093(t *testing.T){ do(128, r("A",93), r("\x23",35), t)}
func Test128x094(t *testing.T){ do(128, r("A",94), r("\x22",34), t)}
func Test128x095(t *testing.T){ do(128, r("A",95), r("\x21",33), t)}
func Test128x096(t *testing.T){ do(128, r("A",96), r("\x20",32), t)}
func Test128x097(t *testing.T){ do(128, r("A",97), r("\x1f",31), t)}
func Test128x098(t *testing.T){ do(128, r("A",98), r("\x1e",30), t)}
func Test128x099(t *testing.T){ do(128, r("A",99), r("\x1d",29), t)}
func Test128x100(t *testing.T){ do(128, r("A",100), r("\x1c",28), t)}
func Test128x101(t *testing.T){ do(128, r("A",101), r("\x1b",27), t)}
func Test128x102(t *testing.T){ do(128, r("A",102), r("\x1a",26), t)}
func Test128x103(t *testing.T){ do(128, r("A",103), r("\x19",25), t)}
func Test128x104(t *testing.T){ do(128, r("A",104), r("\x18",24), t)}
func Test128x105(t *testing.T){ do(128, r("A",105), r("\x17",23), t)}
func Test128x106(t *testing.T){ do(128, r("A",106), r("\x16",22), t)}
func Test128x107(t *testing.T){ do(128, r("A",107), r("\x15",21), t)}
func Test128x108(t *testing.T){ do(128, r("A",108), r("\x14",20), t)}
func Test128x109(t *testing.T){ do(128, r("A",109), r("\x13",19), t)}
func Test128x110(t *testing.T){ do(128, r("A",110), r("\x12",18), t)}
func Test128x111(t *testing.T){ do(128, r("A",111), r("\x11",17), t)}
func Test128x112(t *testing.T){ do(128, r("A",112), r("\x10",16), t)}
func Test128x113(t *testing.T){ do(128, r("A",113), r("\x0f",15), t)}
func Test128x114(t *testing.T){ do(128, r("A",114), r("\x0e",14), t)}
func Test128x115(t *testing.T){ do(128, r("A",115), r("\x0d",13), t)}
func Test128x116(t *testing.T){ do(128, r("A",116), r("\x0c",12), t)}
func Test128x117(t *testing.T){ do(128, r("A",117), r("\x0b",11), t)}
func Test128x118(t *testing.T){ do(128, r("A",118), r("\x0a",10), t)}
func Test128x119(t *testing.T){ do(128, r("A",119), r("\x09", 9), t)}
func Test128x120(t *testing.T){ do(128, r("A",120), r("\x08", 8), t)}
func Test128x121(t *testing.T){ do(128, r("A",121), r("\x07", 7), t)}
func Test128x122(t *testing.T){ do(128, r("A",122), r("\x06", 6), t)}
func Test128x123(t *testing.T){ do(128, r("A",123), r("\x05", 5), t)}
func Test128x124(t *testing.T){ do(128, r("A",124), r("\x04", 4), t)}
func Test128x125(t *testing.T){ do(128, r("A",125), r("\x03", 3), t)}
func Test128x126(t *testing.T){ do(128, r("A",126), r("\x02", 2), t)}
func Test128x127(t *testing.T){ do(128, r("A",127), r("\x01", 1), t)}
func Test128x128(t *testing.T){ do(128, r("A",128), r("\x00",128), t)}
func Test128x129(t *testing.T){ do(128, r("A",129), r("\x7f",127), t)}
func Test128x130(t *testing.T){ do(128, r("A",130), r("\x7e",126), t)}
func Test128x131(t *testing.T){ do(128, r("A",131), r("\x7d",125), t)}
func Test128x132(t *testing.T){ do(128, r("A",132), r("\x7c",124), t)}
func Test128x133(t *testing.T){ do(128, r("A",133), r("\x7b",123), t)}
func Test128x134(t *testing.T){ do(128, r("A",134), r("\x7a",122), t)}
func Test128x135(t *testing.T){ do(128, r("A",135), r("\x79",121), t)}
func Test128x136(t *testing.T){ do(128, r("A",136), r("\x78",120), t)}
func Test128x137(t *testing.T){ do(128, r("A",137), r("\x77",119), t)}
func Test128x138(t *testing.T){ do(128, r("A",138), r("\x76",118), t)}
func Test128x139(t *testing.T){ do(128, r("A",139), r("\x75",117), t)}
func Test128x140(t *testing.T){ do(128, r("A",140), r("\x74",116), t)}
func Test128x141(t *testing.T){ do(128, r("A",141), r("\x73",115), t)}
func Test128x142(t *testing.T){ do(128, r("A",142), r("\x72",114), t)}
func Test128x143(t *testing.T){ do(128, r("A",143), r("\x71",113), t)}
func Test128x144(t *testing.T){ do(128, r("A",144), r("\x70",112), t)}
func Test128x145(t *testing.T){ do(128, r("A",145), r("\x6f",111), t)}
func Test128x146(t *testing.T){ do(128, r("A",146), r("\x6e",110), t)}
func Test128x147(t *testing.T){ do(128, r("A",147), r("\x6d",109), t)}
func Test128x148(t *testing.T){ do(128, r("A",148), r("\x6c",108), t)}
func Test128x149(t *testing.T){ do(128, r("A",149), r("\x6b",107), t)}
func Test128x150(t *testing.T){ do(128, r("A",150), r("\x6a",106), t)}
func Test128x151(t *testing.T){ do(128, r("A",151), r("\x69",105), t)}
func Test128x152(t *testing.T){ do(128, r("A",152), r("\x68",104), t)}
func Test128x153(t *testing.T){ do(128, r("A",153), r("\x67",103), t)}
func Test128x154(t *testing.T){ do(128, r("A",154), r("\x66",102), t)}
func Test128x155(t *testing.T){ do(128, r("A",155), r("\x65",101), t)}
func Test128x156(t *testing.T){ do(128, r("A",156), r("\x64",100), t)}
func Test128x157(t *testing.T){ do(128, r("A",157), r("\x63",99), t)}
func Test128x158(t *testing.T){ do(128, r("A",158), r("\x62",98), t)}
func Test128x159(t *testing.T){ do(128, r("A",159), r("\x61",97), t)}
func Test128x160(t *testing.T){ do(128, r("A",160), r("\x60",96), t)}
func Test128x161(t *testing.T){ do(128, r("A",161), r("\x5f",95), t)}
func Test128x162(t *testing.T){ do(128, r("A",162), r("\x5e",94), t)}
func Test128x163(t *testing.T){ do(128, r("A",163), r("\x5d",93), t)}
func Test128x164(t *testing.T){ do(128, r("A",164), r("\x5c",92), t)}
func Test128x165(t *testing.T){ do(128, r("A",165), r("\x5b",91), t)}
func Test128x166(t *testing.T){ do(128, r("A",166), r("\x5a",90), t)}
func Test128x167(t *testing.T){ do(128, r("A",167), r("\x59",89), t)}
func Test128x168(t *testing.T){ do(128, r("A",168), r("\x58",88), t)}
func Test128x169(t *testing.T){ do(128, r("A",169), r("\x57",87), t)}
func Test128x170(t *testing.T){ do(128, r("A",170), r("\x56",86), t)}
func Test128x171(t *testing.T){ do(128, r("A",171), r("\x55",85), t)}
func Test128x172(t *testing.T){ do(128, r("A",172), r("\x54",84), t)}
func Test128x173(t *testing.T){ do(128, r("A",173), r("\x53",83), t)}
func Test128x174(t *testing.T){ do(128, r("A",174), r("\x52",82), t)}
func Test128x175(t *testing.T){ do(128, r("A",175), r("\x51",81), t)}
func Test128x176(t *testing.T){ do(128, r("A",176), r("\x50",80), t)}
func Test128x177(t *testing.T){ do(128, r("A",177), r("\x4f",79), t)}
func Test128x178(t *testing.T){ do(128, r("A",178), r("\x4e",78), t)}
func Test128x179(t *testing.T){ do(128, r("A",179), r("\x4d",77), t)}
func Test128x180(t *testing.T){ do(128, r("A",180), r("\x4c",76), t)}
func Test128x181(t *testing.T){ do(128, r("A",181), r("\x4b",75), t)}
func Test128x182(t *testing.T){ do(128, r("A",182), r("\x4a",74), t)}
func Test128x183(t *testing.T){ do(128, r("A",183), r("\x49",73), t)}
func Test128x184(t *testing.T){ do(128, r("A",184), r("\x48",72), t)}
func Test128x185(t *testing.T){ do(128, r("A",185), r("\x47",71), t)}
func Test128x186(t *testing.T){ do(128, r("A",186), r("\x46",70), t)}
func Test128x187(t *testing.T){ do(128, r("A",187), r("\x45",69), t)}
func Test128x188(t *testing.T){ do(128, r("A",188), r("\x44",68), t)}
func Test128x189(t *testing.T){ do(128, r("A",189), r("\x43",67), t)}
func Test128x190(t *testing.T){ do(128, r("A",190), r("\x42",66), t)}
func Test128x191(t *testing.T){ do(128, r("A",191), r("\x41",65), t)}
func Test128x192(t *testing.T){ do(128, r("A",192), r("\x40",64), t)}
func Test128x193(t *testing.T){ do(128, r("A",193), r("\x3f",63), t)}
func Test128x194(t *testing.T){ do(128, r("A",194), r("\x3e",62), t)}
func Test128x195(t *testing.T){ do(128, r("A",195), r("\x3d",61), t)}
func Test128x196(t *testing.T){ do(128, r("A",196), r("\x3c",60), t)}
func Test128x197(t *testing.T){ do(128, r("A",197), r("\x3b",59), t)}
func Test128x198(t *testing.T){ do(128, r("A",198), r("\x3a",58), t)}
func Test128x199(t *testing.T){ do(128, r("A",199), r("\x39",57), t)}
func Test128x200(t *testing.T){ do(128, r("A",200), r("\x38",56), t)}
func Test128x201(t *testing.T){ do(128, r("A",201), r("\x37",55), t)}
func Test128x202(t *testing.T){ do(128, r("A",202), r("\x36",54), t)}
func Test128x203(t *testing.T){ do(128, r("A",203), r("\x35",53), t)}
func Test128x204(t *testing.T){ do(128, r("A",204), r("\x34",52), t)}
func Test128x205(t *testing.T){ do(128, r("A",205), r("\x33",51), t)}
func Test128x206(t *testing.T){ do(128, r("A",206), r("\x32",50), t)}
func Test128x207(t *testing.T){ do(128, r("A",207), r("\x31",49), t)}
func Test128x208(t *testing.T){ do(128, r("A",208), r("\x30",48), t)}
func Test128x209(t *testing.T){ do(128, r("A",209), r("\x2f",47), t)}
func Test128x210(t *testing.T){ do(128, r("A",210), r("\x2e",46), t)}
func Test128x211(t *testing.T){ do(128, r("A",211), r("\x2d",45), t)}
func Test128x212(t *testing.T){ do(128, r("A",212), r("\x2c",44), t)}
func Test128x213(t *testing.T){ do(128, r("A",213), r("\x2b",43), t)}
func Test128x214(t *testing.T){ do(128, r("A",214), r("\x2a",42), t)}
func Test128x215(t *testing.T){ do(128, r("A",215), r("\x29",41), t)}
func Test128x216(t *testing.T){ do(128, r("A",216), r("\x28",40), t)}
func Test128x217(t *testing.T){ do(128, r("A",217), r("\x27",39), t)}
func Test128x218(t *testing.T){ do(128, r("A",218), r("\x26",38), t)}
func Test128x219(t *testing.T){ do(128, r("A",219), r("\x25",37), t)}
func Test128x220(t *testing.T){ do(128, r("A",220), r("\x24",36), t)}
func Test128x221(t *testing.T){ do(128, r("A",221), r("\x23",35), t)}
func Test128x222(t *testing.T){ do(128, r("A",222), r("\x22",34), t)}
func Test128x223(t *testing.T){ do(128, r("A",223), r("\x21",33), t)}
func Test128x224(t *testing.T){ do(128, r("A",224), r("\x20",32), t)}
func Test128x225(t *testing.T){ do(128, r("A",225), r("\x1f",31), t)}
func Test128x226(t *testing.T){ do(128, r("A",226), r("\x1e",30), t)}
func Test128x227(t *testing.T){ do(128, r("A",227), r("\x1d",29), t)}
func Test128x228(t *testing.T){ do(128, r("A",228), r("\x1c",28), t)}
func Test128x229(t *testing.T){ do(128, r("A",229), r("\x1b",27), t)}
func Test128x230(t *testing.T){ do(128, r("A",230), r("\x1a",26), t)}
func Test128x231(t *testing.T){ do(128, r("A",231), r("\x19",25), t)}
func Test128x232(t *testing.T){ do(128, r("A",232), r("\x18",24), t)}
func Test128x233(t *testing.T){ do(128, r("A",233), r("\x17",23), t)}
func Test128x234(t *testing.T){ do(128, r("A",234), r("\x16",22), t)}
func Test128x235(t *testing.T){ do(128, r("A",235), r("\x15",21), t)}
func Test128x236(t *testing.T){ do(128, r("A",236), r("\x14",20), t)}
func Test128x237(t *testing.T){ do(128, r("A",237), r("\x13",19), t)}
func Test128x238(t *testing.T){ do(128, r("A",238), r("\x12",18), t)}
func Test128x239(t *testing.T){ do(128, r("A",239), r("\x11",17), t)}
func Test128x240(t *testing.T){ do(128, r("A",240), r("\x10",16), t)}
func Test128x241(t *testing.T){ do(128, r("A",241), r("\x0f",15), t)}
func Test128x242(t *testing.T){ do(128, r("A",242), r("\x0e",14), t)}
func Test128x243(t *testing.T){ do(128, r("A",243), r("\x0d",13), t)}
func Test128x244(t *testing.T){ do(128, r("A",244), r("\x0c",12), t)}
func Test128x245(t *testing.T){ do(128, r("A",245), r("\x0b",11), t)}
func Test128x246(t *testing.T){ do(128, r("A",246), r("\x0a",10), t)}
func Test128x247(t *testing.T){ do(128, r("A",247), r("\x09", 9), t)}
func Test128x248(t *testing.T){ do(128, r("A",248), r("\x08", 8), t)}
func Test128x249(t *testing.T){ do(128, r("A",249), r("\x07", 7), t)}
func Test128x250(t *testing.T){ do(128, r("A",250), r("\x06", 6), t)}
func Test128x251(t *testing.T){ do(128, r("A",251), r("\x05", 5), t)}
func Test128x252(t *testing.T){ do(128, r("A",252), r("\x04", 4), t)}
func Test128x253(t *testing.T){ do(128, r("A",253), r("\x03", 3), t)}
func Test128x254(t *testing.T){ do(128, r("A",254), r("\x02", 2), t)}
func Test128x255(t *testing.T){ do(128, r("A",255), r("\x01", 1), t)}
func Test160x000(t *testing.T){ do(160, r("A", 0), r("\x00",160), t)}
func Test160x001(t *testing.T){ do(160, r("A", 1), r("\x9f",159), t)}
func Test160x002(t *testing.T){ do(160, r("A", 2), r("\x9e",158), t)}
func Test160x003(t *testing.T){ do(160, r("A", 3), r("\x9d",157), t)}
func Test160x004(t *testing.T){ do(160, r("A", 4), r("\x9c",156), t)}
func Test160x005(t *testing.T){ do(160, r("A", 5), r("\x9b",155), t)}
func Test160x006(t *testing.T){ do(160, r("A", 6), r("\x9a",154), t)}
func Test160x007(t *testing.T){ do(160, r("A", 7), r("\x99",153), t)}
func Test160x008(t *testing.T){ do(160, r("A", 8), r("\x98",152), t)}
func Test160x009(t *testing.T){ do(160, r("A", 9), r("\x97",151), t)}
func Test160x010(t *testing.T){ do(160, r("A",10), r("\x96",150), t)}
func Test160x011(t *testing.T){ do(160, r("A",11), r("\x95",149), t)}
func Test160x012(t *testing.T){ do(160, r("A",12), r("\x94",148), t)}
func Test160x013(t *testing.T){ do(160, r("A",13), r("\x93",147), t)}
func Test160x014(t *testing.T){ do(160, r("A",14), r("\x92",146), t)}
func Test160x015(t *testing.T){ do(160, r("A",15), r("\x91",145), t)}
func Test160x016(t *testing.T){ do(160, r("A",16), r("\x90",144), t)}
func Test160x017(t *testing.T){ do(160, r("A",17), r("\x8f",143), t)}
func Test160x018(t *testing.T){ do(160, r("A",18), r("\x8e",142), t)}
func Test160x019(t *testing.T){ do(160, r("A",19), r("\x8d",141), t)}
func Test160x020(t *testing.T){ do(160, r("A",20), r("\x8c",140), t)}
func Test160x021(t *testing.T){ do(160, r("A",21), r("\x8b",139), t)}
func Test160x022(t *testing.T){ do(160, r("A",22), r("\x8a",138), t)}
func Test160x023(t *testing.T){ do(160, r("A",23), r("\x89",137), t)}
func Test160x024(t *testing.T){ do(160, r("A",24), r("\x88",136), t)}
func Test160x025(t *testing.T){ do(160, r("A",25), r("\x87",135), t)}
func Test160x026(t *testing.T){ do(160, r("A",26), r("\x86",134), t)}
func Test160x027(t *testing.T){ do(160, r("A",27), r("\x85",133), t)}
func Test160x028(t *testing.T){ do(160, r("A",28), r("\x84",132), t)}
func Test160x029(t *testing.T){ do(160, r("A",29), r("\x83",131), t)}
func Test160x030(t *testing.T){ do(160, r("A",30), r("\x82",130), t)}
func Test160x031(t *testing.T){ do(160, r("A",31), r("\x81",129), t)}
func Test160x032(t *testing.T){ do(160, r("A",32), r("\x80",128), t)}
func Test160x033(t *testing.T){ do(160, r("A",33), r("\x7f",127), t)}
func Test160x034(t *testing.T){ do(160, r("A",34), r("\x7e",126), t)}
func Test160x035(t *testing.T){ do(160, r("A",35), r("\x7d",125), t)}
func Test160x036(t *testing.T){ do(160, r("A",36), r("\x7c",124), t)}
func Test160x037(t *testing.T){ do(160, r("A",37), r("\x7b",123), t)}
func Test160x038(t *testing.T){ do(160, r("A",38), r("\x7a",122), t)}
func Test160x039(t *testing.T){ do(160, r("A",39), r("\x79",121), t)}
func Test160x040(t *testing.T){ do(160, r("A",40), r("\x78",120), t)}
func Test160x041(t *testing.T){ do(160, r("A",41), r("\x77",119), t)}
func Test160x042(t *testing.T){ do(160, r("A",42), r("\x76",118), t)}
func Test160x043(t *testing.T){ do(160, r("A",43), r("\x75",117), t)}
func Test160x044(t *testing.T){ do(160, r("A",44), r("\x74",116), t)}
func Test160x045(t *testing.T){ do(160, r("A",45), r("\x73",115), t)}
func Test160x046(t *testing.T){ do(160, r("A",46), r("\x72",114), t)}
func Test160x047(t *testing.T){ do(160, r("A",47), r("\x71",113), t)}
func Test160x048(t *testing.T){ do(160, r("A",48), r("\x70",112), t)}
func Test160x049(t *testing.T){ do(160, r("A",49), r("\x6f",111), t)}
func Test160x050(t *testing.T){ do(160, r("A",50), r("\x6e",110), t)}
func Test160x051(t *testing.T){ do(160, r("A",51), r("\x6d",109), t)}
func Test160x052(t *testing.T){ do(160, r("A",52), r("\x6c",108), t)}
func Test160x053(t *testing.T){ do(160, r("A",53), r("\x6b",107), t)}
func Test160x054(t *testing.T){ do(160, r("A",54), r("\x6a",106), t)}
func Test160x055(t *testing.T){ do(160, r("A",55), r("\x69",105), t)}
func Test160x056(t *testing.T){ do(160, r("A",56), r("\x68",104), t)}
func Test160x057(t *testing.T){ do(160, r("A",57), r("\x67",103), t)}
func Test160x058(t *testing.T){ do(160, r("A",58), r("\x66",102), t)}
func Test160x059(t *testing.T){ do(160, r("A",59), r("\x65",101), t)}
func Test160x060(t *testing.T){ do(160, r("A",60), r("\x64",100), t)}
func Test160x061(t *testing.T){ do(160, r("A",61), r("\x63",99), t)}
func Test160x062(t *testing.T){ do(160, r("A",62), r("\x62",98), t)}
func Test160x063(t *testing.T){ do(160, r("A",63), r("\x61",97), t)}
func Test160x064(t *testing.T){ do(160, r("A",64), r("\x60",96), t)}
func Test160x065(t *testing.T){ do(160, r("A",65), r("\x5f",95), t)}
func Test160x066(t *testing.T){ do(160, r("A",66), r("\x5e",94), t)}
func Test160x067(t *testing.T){ do(160, r("A",67), r("\x5d",93), t)}
func Test160x068(t *testing.T){ do(160, r("A",68), r("\x5c",92), t)}
func Test160x069(t *testing.T){ do(160, r("A",69), r("\x5b",91), t)}
func Test160x070(t *testing.T){ do(160, r("A",70), r("\x5a",90), t)}
func Test160x071(t *testing.T){ do(160, r("A",71), r("\x59",89), t)}
func Test160x072(t *testing.T){ do(160, r("A",72), r("\x58",88), t)}
func Test160x073(t *testing.T){ do(160, r("A",73), r("\x57",87), t)}
func Test160x074(t *testing.T){ do(160, r("A",74), r("\x56",86), t)}
func Test160x075(t *testing.T){ do(160, r("A",75), r("\x55",85), t)}
func Test160x076(t *testing.T){ do(160, r("A",76), r("\x54",84), t)}
func Test160x077(t *testing.T){ do(160, r("A",77), r("\x53",83), t)}
func Test160x078(t *testing.T){ do(160, r("A",78), r("\x52",82), t)}
func Test160x079(t *testing.T){ do(160, r("A",79), r("\x51",81), t)}
func Test160x080(t *testing.T){ do(160, r("A",80), r("\x50",80), t)}
func Test160x081(t *testing.T){ do(160, r("A",81), r("\x4f",79), t)}
func Test160x082(t *testing.T){ do(160, r("A",82), r("\x4e",78), t)}
func Test160x083(t *testing.T){ do(160, r("A",83), r("\x4d",77), t)}
func Test160x084(t *testing.T){ do(160, r("A",84), r("\x4c",76), t)}
func Test160x085(t *testing.T){ do(160, r("A",85), r("\x4b",75), t)}
func Test160x086(t *testing.T){ do(160, r("A",86), r("\x4a",74), t)}
func Test160x087(t *testing.T){ do(160, r("A",87), r("\x49",73), t)}
func Test160x088(t *testing.T){ do(160, r("A",88), r("\x48",72), t)}
func Test160x089(t *testing.T){ do(160, r("A",89), r("\x47",71), t)}
func Test160x090(t *testing.T){ do(160, r("A",90), r("\x46",70), t)}
func Test160x091(t *testing.T){ do(160, r("A",91), r("\x45",69), t)}
func Test160x092(t *testing.T){ do(160, r("A",92), r("\x44",68), t)}
func Test160x093(t *testing.T){ do(160, r("A",93), r("\x43",67), t)}
func Test160x094(t *testing.T){ do(160, r("A",94), r("\x42",66), t)}
func Test160x095(t *testing.T){ do(160, r("A",95), r("\x41",65), t)}
func Test160x096(t *testing.T){ do(160, r("A",96), r("\x40",64), t)}
func Test160x097(t *testing.T){ do(160, r("A",97), r("\x3f",63), t)}
func Test160x098(t *testing.T){ do(160, r("A",98), r("\x3e",62), t)}
func Test160x099(t *testing.T){ do(160, r("A",99), r("\x3d",61), t)}
func Test160x100(t *testing.T){ do(160, r("A",100), r("\x3c",60), t)}
func Test160x101(t *testing.T){ do(160, r("A",101), r("\x3b",59), t)}
func Test160x102(t *testing.T){ do(160, r("A",102), r("\x3a",58), t)}
func Test160x103(t *testing.T){ do(160, r("A",103), r("\x39",57), t)}
func Test160x104(t *testing.T){ do(160, r("A",104), r("\x38",56), t)}
func Test160x105(t *testing.T){ do(160, r("A",105), r("\x37",55), t)}
func Test160x106(t *testing.T){ do(160, r("A",106), r("\x36",54), t)}
func Test160x107(t *testing.T){ do(160, r("A",107), r("\x35",53), t)}
func Test160x108(t *testing.T){ do(160, r("A",108), r("\x34",52), t)}
func Test160x109(t *testing.T){ do(160, r("A",109), r("\x33",51), t)}
func Test160x110(t *testing.T){ do(160, r("A",110), r("\x32",50), t)}
func Test160x111(t *testing.T){ do(160, r("A",111), r("\x31",49), t)}
func Test160x112(t *testing.T){ do(160, r("A",112), r("\x30",48), t)}
func Test160x113(t *testing.T){ do(160, r("A",113), r("\x2f",47), t)}
func Test160x114(t *testing.T){ do(160, r("A",114), r("\x2e",46), t)}
func Test160x115(t *testing.T){ do(160, r("A",115), r("\x2d",45), t)}
func Test160x116(t *testing.T){ do(160, r("A",116), r("\x2c",44), t)}
func Test160x117(t *testing.T){ do(160, r("A",117), r("\x2b",43), t)}
func Test160x118(t *testing.T){ do(160, r("A",118), r("\x2a",42), t)}
func Test160x119(t *testing.T){ do(160, r("A",119), r("\x29",41), t)}
func Test160x120(t *testing.T){ do(160, r("A",120), r("\x28",40), t)}
func Test160x121(t *testing.T){ do(160, r("A",121), r("\x27",39), t)}
func Test160x122(t *testing.T){ do(160, r("A",122), r("\x26",38), t)}
func Test160x123(t *testing.T){ do(160, r("A",123), r("\x25",37), t)}
func Test160x124(t *testing.T){ do(160, r("A",124), r("\x24",36), t)}
func Test160x125(t *testing.T){ do(160, r("A",125), r("\x23",35), t)}
func Test160x126(t *testing.T){ do(160, r("A",126), r("\x22",34), t)}
func Test160x127(t *testing.T){ do(160, r("A",127), r("\x21",33), t)}
func Test160x128(t *testing.T){ do(160, r("A",128), r("\x20",32), t)}
func Test160x129(t *testing.T){ do(160, r("A",129), r("\x1f",31), t)}
func Test160x130(t *testing.T){ do(160, r("A",130), r("\x1e",30), t)}
func Test160x131(t *testing.T){ do(160, r("A",131), r("\x1d",29), t)}
func Test160x132(t *testing.T){ do(160, r("A",132), r("\x1c",28), t)}
func Test160x133(t *testing.T){ do(160, r("A",133), r("\x1b",27), t)}
func Test160x134(t *testing.T){ do(160, r("A",134), r("\x1a",26), t)}
func Test160x135(t *testing.T){ do(160, r("A",135), r("\x19",25), t)}
func Test160x136(t *testing.T){ do(160, r("A",136), r("\x18",24), t)}
func Test160x137(t *testing.T){ do(160, r("A",137), r("\x17",23), t)}
func Test160x138(t *testing.T){ do(160, r("A",138), r("\x16",22), t)}
func Test160x139(t *testing.T){ do(160, r("A",139), r("\x15",21), t)}
func Test160x140(t *testing.T){ do(160, r("A",140), r("\x14",20), t)}
func Test160x141(t *testing.T){ do(160, r("A",141), r("\x13",19), t)}
func Test160x142(t *testing.T){ do(160, r("A",142), r("\x12",18), t)}
func Test160x143(t *testing.T){ do(160, r("A",143), r("\x11",17), t)}
func Test160x144(t *testing.T){ do(160, r("A",144), r("\x10",16), t)}
func Test160x145(t *testing.T){ do(160, r("A",145), r("\x0f",15), t)}
func Test160x146(t *testing.T){ do(160, r("A",146), r("\x0e",14), t)}
func Test160x147(t *testing.T){ do(160, r("A",147), r("\x0d",13), t)}
func Test160x148(t *testing.T){ do(160, r("A",148), r("\x0c",12), t)}
func Test160x149(t *testing.T){ do(160, r("A",149), r("\x0b",11), t)}
func Test160x150(t *testing.T){ do(160, r("A",150), r("\x0a",10), t)}
func Test160x151(t *testing.T){ do(160, r("A",151), r("\x09", 9), t)}
func Test160x152(t *testing.T){ do(160, r("A",152), r("\x08", 8), t)}
func Test160x153(t *testing.T){ do(160, r("A",153), r("\x07", 7), t)}
func Test160x154(t *testing.T){ do(160, r("A",154), r("\x06", 6), t)}
func Test160x155(t *testing.T){ do(160, r("A",155), r("\x05", 5), t)}
func Test160x156(t *testing.T){ do(160, r("A",156), r("\x04", 4), t)}
func Test160x157(t *testing.T){ do(160, r("A",157), r("\x03", 3), t)}
func Test160x158(t *testing.T){ do(160, r("A",158), r("\x02", 2), t)}
func Test160x159(t *testing.T){ do(160, r("A",159), r("\x01", 1), t)}
func Test160x160(t *testing.T){ do(160, r("A",160), r("\x00",160), t)}
func Test160x161(t *testing.T){ do(160, r("A",161), r("\x9f",159), t)}
func Test160x162(t *testing.T){ do(160, r("A",162), r("\x9e",158), t)}
func Test160x163(t *testing.T){ do(160, r("A",163), r("\x9d",157), t)}
func Test160x164(t *testing.T){ do(160, r("A",164), r("\x9c",156), t)}
func Test160x165(t *testing.T){ do(160, r("A",165), r("\x9b",155), t)}
func Test160x166(t *testing.T){ do(160, r("A",166), r("\x9a",154), t)}
func Test160x167(t *testing.T){ do(160, r("A",167), r("\x99",153), t)}
func Test160x168(t *testing.T){ do(160, r("A",168), r("\x98",152), t)}
func Test160x169(t *testing.T){ do(160, r("A",169), r("\x97",151), t)}
func Test160x170(t *testing.T){ do(160, r("A",170), r("\x96",150), t)}
func Test160x171(t *testing.T){ do(160, r("A",171), r("\x95",149), t)}
func Test160x172(t *testing.T){ do(160, r("A",172), r("\x94",148), t)}
func Test160x173(t *testing.T){ do(160, r("A",173), r("\x93",147), t)}
func Test160x174(t *testing.T){ do(160, r("A",174), r("\x92",146), t)}
func Test160x175(t *testing.T){ do(160, r("A",175), r("\x91",145), t)}
func Test160x176(t *testing.T){ do(160, r("A",176), r("\x90",144), t)}
func Test160x177(t *testing.T){ do(160, r("A",177), r("\x8f",143), t)}
func Test160x178(t *testing.T){ do(160, r("A",178), r("\x8e",142), t)}
func Test160x179(t *testing.T){ do(160, r("A",179), r("\x8d",141), t)}
func Test160x180(t *testing.T){ do(160, r("A",180), r("\x8c",140), t)}
func Test160x181(t *testing.T){ do(160, r("A",181), r("\x8b",139), t)}
func Test160x182(t *testing.T){ do(160, r("A",182), r("\x8a",138), t)}
func Test160x183(t *testing.T){ do(160, r("A",183), r("\x89",137), t)}
func Test160x184(t *testing.T){ do(160, r("A",184), r("\x88",136), t)}
func Test160x185(t *testing.T){ do(160, r("A",185), r("\x87",135), t)}
func Test160x186(t *testing.T){ do(160, r("A",186), r("\x86",134), t)}
func Test160x187(t *testing.T){ do(160, r("A",187), r("\x85",133), t)}
func Test160x188(t *testing.T){ do(160, r("A",188), r("\x84",132), t)}
func Test160x189(t *testing.T){ do(160, r("A",189), r("\x83",131), t)}
func Test160x190(t *testing.T){ do(160, r("A",190), r("\x82",130), t)}
func Test160x191(t *testing.T){ do(160, r("A",191), r("\x81",129), t)}
func Test160x192(t *testing.T){ do(160, r("A",192), r("\x80",128), t)}
func Test160x193(t *testing.T){ do(160, r("A",193), r("\x7f",127), t)}
func Test160x194(t *testing.T){ do(160, r("A",194), r("\x7e",126), t)}
func Test160x195(t *testing.T){ do(160, r("A",195), r("\x7d",125), t)}
func Test160x196(t *testing.T){ do(160, r("A",196), r("\x7c",124), t)}
func Test160x197(t *testing.T){ do(160, r("A",197), r("\x7b",123), t)}
func Test160x198(t *testing.T){ do(160, r("A",198), r("\x7a",122), t)}
func Test160x199(t *testing.T){ do(160, r("A",199), r("\x79",121), t)}
func Test160x200(t *testing.T){ do(160, r("A",200), r("\x78",120), t)}
func Test160x201(t *testing.T){ do(160, r("A",201), r("\x77",119), t)}
func Test160x202(t *testing.T){ do(160, r("A",202), r("\x76",118), t)}
func Test160x203(t *testing.T){ do(160, r("A",203), r("\x75",117), t)}
func Test160x204(t *testing.T){ do(160, r("A",204), r("\x74",116), t)}
func Test160x205(t *testing.T){ do(160, r("A",205), r("\x73",115), t)}
func Test160x206(t *testing.T){ do(160, r("A",206), r("\x72",114), t)}
func Test160x207(t *testing.T){ do(160, r("A",207), r("\x71",113), t)}
func Test160x208(t *testing.T){ do(160, r("A",208), r("\x70",112), t)}
func Test160x209(t *testing.T){ do(160, r("A",209), r("\x6f",111), t)}
func Test160x210(t *testing.T){ do(160, r("A",210), r("\x6e",110), t)}
func Test160x211(t *testing.T){ do(160, r("A",211), r("\x6d",109), t)}
func Test160x212(t *testing.T){ do(160, r("A",212), r("\x6c",108), t)}
func Test160x213(t *testing.T){ do(160, r("A",213), r("\x6b",107), t)}
func Test160x214(t *testing.T){ do(160, r("A",214), r("\x6a",106), t)}
func Test160x215(t *testing.T){ do(160, r("A",215), r("\x69",105), t)}
func Test160x216(t *testing.T){ do(160, r("A",216), r("\x68",104), t)}
func Test160x217(t *testing.T){ do(160, r("A",217), r("\x67",103), t)}
func Test160x218(t *testing.T){ do(160, r("A",218), r("\x66",102), t)}
func Test160x219(t *testing.T){ do(160, r("A",219), r("\x65",101), t)}
func Test160x220(t *testing.T){ do(160, r("A",220), r("\x64",100), t)}
func Test160x221(t *testing.T){ do(160, r("A",221), r("\x63",99), t)}
func Test160x222(t *testing.T){ do(160, r("A",222), r("\x62",98), t)}
func Test160x223(t *testing.T){ do(160, r("A",223), r("\x61",97), t)}
func Test160x224(t *testing.T){ do(160, r("A",224), r("\x60",96), t)}
func Test160x225(t *testing.T){ do(160, r("A",225), r("\x5f",95), t)}
func Test160x226(t *testing.T){ do(160, r("A",226), r("\x5e",94), t)}
func Test160x227(t *testing.T){ do(160, r("A",227), r("\x5d",93), t)}
func Test160x228(t *testing.T){ do(160, r("A",228), r("\x5c",92), t)}
func Test160x229(t *testing.T){ do(160, r("A",229), r("\x5b",91), t)}
func Test160x230(t *testing.T){ do(160, r("A",230), r("\x5a",90), t)}
func Test160x231(t *testing.T){ do(160, r("A",231), r("\x59",89), t)}
func Test160x232(t *testing.T){ do(160, r("A",232), r("\x58",88), t)}
func Test160x233(t *testing.T){ do(160, r("A",233), r("\x57",87), t)}
func Test160x234(t *testing.T){ do(160, r("A",234), r("\x56",86), t)}
func Test160x235(t *testing.T){ do(160, r("A",235), r("\x55",85), t)}
func Test160x236(t *testing.T){ do(160, r("A",236), r("\x54",84), t)}
func Test160x237(t *testing.T){ do(160, r("A",237), r("\x53",83), t)}
func Test160x238(t *testing.T){ do(160, r("A",238), r("\x52",82), t)}
func Test160x239(t *testing.T){ do(160, r("A",239), r("\x51",81), t)}
func Test160x240(t *testing.T){ do(160, r("A",240), r("\x50",80), t)}
func Test160x241(t *testing.T){ do(160, r("A",241), r("\x4f",79), t)}
func Test160x242(t *testing.T){ do(160, r("A",242), r("\x4e",78), t)}
func Test160x243(t *testing.T){ do(160, r("A",243), r("\x4d",77), t)}
func Test160x244(t *testing.T){ do(160, r("A",244), r("\x4c",76), t)}
func Test160x245(t *testing.T){ do(160, r("A",245), r("\x4b",75), t)}
func Test160x246(t *testing.T){ do(160, r("A",246), r("\x4a",74), t)}
func Test160x247(t *testing.T){ do(160, r("A",247), r("\x49",73), t)}
func Test160x248(t *testing.T){ do(160, r("A",248), r("\x48",72), t)}
func Test160x249(t *testing.T){ do(160, r("A",249), r("\x47",71), t)}
func Test160x250(t *testing.T){ do(160, r("A",250), r("\x46",70), t)}
func Test160x251(t *testing.T){ do(160, r("A",251), r("\x45",69), t)}
func Test160x252(t *testing.T){ do(160, r("A",252), r("\x44",68), t)}
func Test160x253(t *testing.T){ do(160, r("A",253), r("\x43",67), t)}
func Test160x254(t *testing.T){ do(160, r("A",254), r("\x42",66), t)}
func Test160x255(t *testing.T){ do(160, r("A",255), r("\x41",65), t)}
func Test192x000(t *testing.T){ do(192, r("A", 0), r("\x00",192), t)}
func Test192x001(t *testing.T){ do(192, r("A", 1), r("\xbf",191), t)}
func Test192x002(t *testing.T){ do(192, r("A", 2), r("\xbe",190), t)}
func Test192x003(t *testing.T){ do(192, r("A", 3), r("\xbd",189), t)}
func Test192x004(t *testing.T){ do(192, r("A", 4), r("\xbc",188), t)}
func Test192x005(t *testing.T){ do(192, r("A", 5), r("\xbb",187), t)}
func Test192x006(t *testing.T){ do(192, r("A", 6), r("\xba",186), t)}
func Test192x007(t *testing.T){ do(192, r("A", 7), r("\xb9",185), t)}
func Test192x008(t *testing.T){ do(192, r("A", 8), r("\xb8",184), t)}
func Test192x009(t *testing.T){ do(192, r("A", 9), r("\xb7",183), t)}
func Test192x010(t *testing.T){ do(192, r("A",10), r("\xb6",182), t)}
func Test192x011(t *testing.T){ do(192, r("A",11), r("\xb5",181), t)}
func Test192x012(t *testing.T){ do(192, r("A",12), r("\xb4",180), t)}
func Test192x013(t *testing.T){ do(192, r("A",13), r("\xb3",179), t)}
func Test192x014(t *testing.T){ do(192, r("A",14), r("\xb2",178), t)}
func Test192x015(t *testing.T){ do(192, r("A",15), r("\xb1",177), t)}
func Test192x016(t *testing.T){ do(192, r("A",16), r("\xb0",176), t)}
func Test192x017(t *testing.T){ do(192, r("A",17), r("\xaf",175), t)}
func Test192x018(t *testing.T){ do(192, r("A",18), r("\xae",174), t)}
func Test192x019(t *testing.T){ do(192, r("A",19), r("\xad",173), t)}
func Test192x020(t *testing.T){ do(192, r("A",20), r("\xac",172), t)}
func Test192x021(t *testing.T){ do(192, r("A",21), r("\xab",171), t)}
func Test192x022(t *testing.T){ do(192, r("A",22), r("\xaa",170), t)}
func Test192x023(t *testing.T){ do(192, r("A",23), r("\xa9",169), t)}
func Test192x024(t *testing.T){ do(192, r("A",24), r("\xa8",168), t)}
func Test192x025(t *testing.T){ do(192, r("A",25), r("\xa7",167), t)}
func Test192x026(t *testing.T){ do(192, r("A",26), r("\xa6",166), t)}
func Test192x027(t *testing.T){ do(192, r("A",27), r("\xa5",165), t)}
func Test192x028(t *testing.T){ do(192, r("A",28), r("\xa4",164), t)}
func Test192x029(t *testing.T){ do(192, r("A",29), r("\xa3",163), t)}
func Test192x030(t *testing.T){ do(192, r("A",30), r("\xa2",162), t)}
func Test192x031(t *testing.T){ do(192, r("A",31), r("\xa1",161), t)}
func Test192x032(t *testing.T){ do(192, r("A",32), r("\xa0",160), t)}
func Test192x033(t *testing.T){ do(192, r("A",33), r("\x9f",159), t)}
func Test192x034(t *testing.T){ do(192, r("A",34), r("\x9e",158), t)}
func Test192x035(t *testing.T){ do(192, r("A",35), r("\x9d",157), t)}
func Test192x036(t *testing.T){ do(192, r("A",36), r("\x9c",156), t)}
func Test192x037(t *testing.T){ do(192, r("A",37), r("\x9b",155), t)}
func Test192x038(t *testing.T){ do(192, r("A",38), r("\x9a",154), t)}
func Test192x039(t *testing.T){ do(192, r("A",39), r("\x99",153), t)}
func Test192x040(t *testing.T){ do(192, r("A",40), r("\x98",152), t)}
func Test192x041(t *testing.T){ do(192, r("A",41), r("\x97",151), t)}
func Test192x042(t *testing.T){ do(192, r("A",42), r("\x96",150), t)}
func Test192x043(t *testing.T){ do(192, r("A",43), r("\x95",149), t)}
func Test192x044(t *testing.T){ do(192, r("A",44), r("\x94",148), t)}
func Test192x045(t *testing.T){ do(192, r("A",45), r("\x93",147), t)}
func Test192x046(t *testing.T){ do(192, r("A",46), r("\x92",146), t)}
func Test192x047(t *testing.T){ do(192, r("A",47), r("\x91",145), t)}
func Test192x048(t *testing.T){ do(192, r("A",48), r("\x90",144), t)}
func Test192x049(t *testing.T){ do(192, r("A",49), r("\x8f",143), t)}
func Test192x050(t *testing.T){ do(192, r("A",50), r("\x8e",142), t)}
func Test192x051(t *testing.T){ do(192, r("A",51), r("\x8d",141), t)}
func Test192x052(t *testing.T){ do(192, r("A",52), r("\x8c",140), t)}
func Test192x053(t *testing.T){ do(192, r("A",53), r("\x8b",139), t)}
func Test192x054(t *testing.T){ do(192, r("A",54), r("\x8a",138), t)}
func Test192x055(t *testing.T){ do(192, r("A",55), r("\x89",137), t)}
func Test192x056(t *testing.T){ do(192, r("A",56), r("\x88",136), t)}
func Test192x057(t *testing.T){ do(192, r("A",57), r("\x87",135), t)}
func Test192x058(t *testing.T){ do(192, r("A",58), r("\x86",134), t)}
func Test192x059(t *testing.T){ do(192, r("A",59), r("\x85",133), t)}
func Test192x060(t *testing.T){ do(192, r("A",60), r("\x84",132), t)}
func Test192x061(t *testing.T){ do(192, r("A",61), r("\x83",131), t)}
func Test192x062(t *testing.T){ do(192, r("A",62), r("\x82",130), t)}
func Test192x063(t *testing.T){ do(192, r("A",63), r("\x81",129), t)}
func Test192x064(t *testing.T){ do(192, r("A",64), r("\x80",128), t)}
func Test192x065(t *testing.T){ do(192, r("A",65), r("\x7f",127), t)}
func Test192x066(t *testing.T){ do(192, r("A",66), r("\x7e",126), t)}
func Test192x067(t *testing.T){ do(192, r("A",67), r("\x7d",125), t)}
func Test192x068(t *testing.T){ do(192, r("A",68), r("\x7c",124), t)}
func Test192x069(t *testing.T){ do(192, r("A",69), r("\x7b",123), t)}
func Test192x070(t *testing.T){ do(192, r("A",70), r("\x7a",122), t)}
func Test192x071(t *testing.T){ do(192, r("A",71), r("\x79",121), t)}
func Test192x072(t *testing.T){ do(192, r("A",72), r("\x78",120), t)}
func Test192x073(t *testing.T){ do(192, r("A",73), r("\x77",119), t)}
func Test192x074(t *testing.T){ do(192, r("A",74), r("\x76",118), t)}
func Test192x075(t *testing.T){ do(192, r("A",75), r("\x75",117), t)}
func Test192x076(t *testing.T){ do(192, r("A",76), r("\x74",116), t)}
func Test192x077(t *testing.T){ do(192, r("A",77), r("\x73",115), t)}
func Test192x078(t *testing.T){ do(192, r("A",78), r("\x72",114), t)}
func Test192x079(t *testing.T){ do(192, r("A",79), r("\x71",113), t)}
func Test192x080(t *testing.T){ do(192, r("A",80), r("\x70",112), t)}
func Test192x081(t *testing.T){ do(192, r("A",81), r("\x6f",111), t)}
func Test192x082(t *testing.T){ do(192, r("A",82), r("\x6e",110), t)}
func Test192x083(t *testing.T){ do(192, r("A",83), r("\x6d",109), t)}
func Test192x084(t *testing.T){ do(192, r("A",84), r("\x6c",108), t)}
func Test192x085(t *testing.T){ do(192, r("A",85), r("\x6b",107), t)}
func Test192x086(t *testing.T){ do(192, r("A",86), r("\x6a",106), t)}
func Test192x087(t *testing.T){ do(192, r("A",87), r("\x69",105), t)}
func Test192x088(t *testing.T){ do(192, r("A",88), r("\x68",104), t)}
func Test192x089(t *testing.T){ do(192, r("A",89), r("\x67",103), t)}
func Test192x090(t *testing.T){ do(192, r("A",90), r("\x66",102), t)}
func Test192x091(t *testing.T){ do(192, r("A",91), r("\x65",101), t)}
func Test192x092(t *testing.T){ do(192, r("A",92), r("\x64",100), t)}
func Test192x093(t *testing.T){ do(192, r("A",93), r("\x63",99), t)}
func Test192x094(t *testing.T){ do(192, r("A",94), r("\x62",98), t)}
func Test192x095(t *testing.T){ do(192, r("A",95), r("\x61",97), t)}
func Test192x096(t *testing.T){ do(192, r("A",96), r("\x60",96), t)}
func Test192x097(t *testing.T){ do(192, r("A",97), r("\x5f",95), t)}
func Test192x098(t *testing.T){ do(192, r("A",98), r("\x5e",94), t)}
func Test192x099(t *testing.T){ do(192, r("A",99), r("\x5d",93), t)}
func Test192x100(t *testing.T){ do(192, r("A",100), r("\x5c",92), t)}
func Test192x101(t *testing.T){ do(192, r("A",101), r("\x5b",91), t)}
func Test192x102(t *testing.T){ do(192, r("A",102), r("\x5a",90), t)}
func Test192x103(t *testing.T){ do(192, r("A",103), r("\x59",89), t)}
func Test192x104(t *testing.T){ do(192, r("A",104), r("\x58",88), t)}
func Test192x105(t *testing.T){ do(192, r("A",105), r("\x57",87), t)}
func Test192x106(t *testing.T){ do(192, r("A",106), r("\x56",86), t)}
func Test192x107(t *testing.T){ do(192, r("A",107), r("\x55",85), t)}
func Test192x108(t *testing.T){ do(192, r("A",108), r("\x54",84), t)}
func Test192x109(t *testing.T){ do(192, r("A",109), r("\x53",83), t)}
func Test192x110(t *testing.T){ do(192, r("A",110), r("\x52",82), t)}
func Test192x111(t *testing.T){ do(192, r("A",111), r("\x51",81), t)}
func Test192x112(t *testing.T){ do(192, r("A",112), r("\x50",80), t)}
func Test192x113(t *testing.T){ do(192, r("A",113), r("\x4f",79), t)}
func Test192x114(t *testing.T){ do(192, r("A",114), r("\x4e",78), t)}
func Test192x115(t *testing.T){ do(192, r("A",115), r("\x4d",77), t)}
func Test192x116(t *testing.T){ do(192, r("A",116), r("\x4c",76), t)}
func Test192x117(t *testing.T){ do(192, r("A",117), r("\x4b",75), t)}
func Test192x118(t *testing.T){ do(192, r("A",118), r("\x4a",74), t)}
func Test192x119(t *testing.T){ do(192, r("A",119), r("\x49",73), t)}
func Test192x120(t *testing.T){ do(192, r("A",120), r("\x48",72), t)}
func Test192x121(t *testing.T){ do(192, r("A",121), r("\x47",71), t)}
func Test192x122(t *testing.T){ do(192, r("A",122), r("\x46",70), t)}
func Test192x123(t *testing.T){ do(192, r("A",123), r("\x45",69), t)}
func Test192x124(t *testing.T){ do(192, r("A",124), r("\x44",68), t)}
func Test192x125(t *testing.T){ do(192, r("A",125), r("\x43",67), t)}
func Test192x126(t *testing.T){ do(192, r("A",126), r("\x42",66), t)}
func Test192x127(t *testing.T){ do(192, r("A",127), r("\x41",65), t)}
func Test192x128(t *testing.T){ do(192, r("A",128), r("\x40",64), t)}
func Test192x129(t *testing.T){ do(192, r("A",129), r("\x3f",63), t)}
func Test192x130(t *testing.T){ do(192, r("A",130), r("\x3e",62), t)}
func Test192x131(t *testing.T){ do(192, r("A",131), r("\x3d",61), t)}
func Test192x132(t *testing.T){ do(192, r("A",132), r("\x3c",60), t)}
func Test192x133(t *testing.T){ do(192, r("A",133), r("\x3b",59), t)}
func Test192x134(t *testing.T){ do(192, r("A",134), r("\x3a",58), t)}
func Test192x135(t *testing.T){ do(192, r("A",135), r("\x39",57), t)}
func Test192x136(t *testing.T){ do(192, r("A",136), r("\x38",56), t)}
func Test192x137(t *testing.T){ do(192, r("A",137), r("\x37",55), t)}
func Test192x138(t *testing.T){ do(192, r("A",138), r("\x36",54), t)}
func Test192x139(t *testing.T){ do(192, r("A",139), r("\x35",53), t)}
func Test192x140(t *testing.T){ do(192, r("A",140), r("\x34",52), t)}
func Test192x141(t *testing.T){ do(192, r("A",141), r("\x33",51), t)}
func Test192x142(t *testing.T){ do(192, r("A",142), r("\x32",50), t)}
func Test192x143(t *testing.T){ do(192, r("A",143), r("\x31",49), t)}
func Test192x144(t *testing.T){ do(192, r("A",144), r("\x30",48), t)}
func Test192x145(t *testing.T){ do(192, r("A",145), r("\x2f",47), t)}
func Test192x146(t *testing.T){ do(192, r("A",146), r("\x2e",46), t)}
func Test192x147(t *testing.T){ do(192, r("A",147), r("\x2d",45), t)}
func Test192x148(t *testing.T){ do(192, r("A",148), r("\x2c",44), t)}
func Test192x149(t *testing.T){ do(192, r("A",149), r("\x2b",43), t)}
func Test192x150(t *testing.T){ do(192, r("A",150), r("\x2a",42), t)}
func Test192x151(t *testing.T){ do(192, r("A",151), r("\x29",41), t)}
func Test192x152(t *testing.T){ do(192, r("A",152), r("\x28",40), t)}
func Test192x153(t *testing.T){ do(192, r("A",153), r("\x27",39), t)}
func Test192x154(t *testing.T){ do(192, r("A",154), r("\x26",38), t)}
func Test192x155(t *testing.T){ do(192, r("A",155), r("\x25",37), t)}
func Test192x156(t *testing.T){ do(192, r("A",156), r("\x24",36), t)}
func Test192x157(t *testing.T){ do(192, r("A",157), r("\x23",35), t)}
func Test192x158(t *testing.T){ do(192, r("A",158), r("\x22",34), t)}
func Test192x159(t *testing.T){ do(192, r("A",159), r("\x21",33), t)}
func Test192x160(t *testing.T){ do(192, r("A",160), r("\x20",32), t)}
func Test192x161(t *testing.T){ do(192, r("A",161), r("\x1f",31), t)}
func Test192x162(t *testing.T){ do(192, r("A",162), r("\x1e",30), t)}
func Test192x163(t *testing.T){ do(192, r("A",163), r("\x1d",29), t)}
func Test192x164(t *testing.T){ do(192, r("A",164), r("\x1c",28), t)}
func Test192x165(t *testing.T){ do(192, r("A",165), r("\x1b",27), t)}
func Test192x166(t *testing.T){ do(192, r("A",166), r("\x1a",26), t)}
func Test192x167(t *testing.T){ do(192, r("A",167), r("\x19",25), t)}
func Test192x168(t *testing.T){ do(192, r("A",168), r("\x18",24), t)}
func Test192x169(t *testing.T){ do(192, r("A",169), r("\x17",23), t)}
func Test192x170(t *testing.T){ do(192, r("A",170), r("\x16",22), t)}
func Test192x171(t *testing.T){ do(192, r("A",171), r("\x15",21), t)}
func Test192x172(t *testing.T){ do(192, r("A",172), r("\x14",20), t)}
func Test192x173(t *testing.T){ do(192, r("A",173), r("\x13",19), t)}
func Test192x174(t *testing.T){ do(192, r("A",174), r("\x12",18), t)}
func Test192x175(t *testing.T){ do(192, r("A",175), r("\x11",17), t)}
func Test192x176(t *testing.T){ do(192, r("A",176), r("\x10",16), t)}
func Test192x177(t *testing.T){ do(192, r("A",177), r("\x0f",15), t)}
func Test192x178(t *testing.T){ do(192, r("A",178), r("\x0e",14), t)}
func Test192x179(t *testing.T){ do(192, r("A",179), r("\x0d",13), t)}
func Test192x180(t *testing.T){ do(192, r("A",180), r("\x0c",12), t)}
func Test192x181(t *testing.T){ do(192, r("A",181), r("\x0b",11), t)}
func Test192x182(t *testing.T){ do(192, r("A",182), r("\x0a",10), t)}
func Test192x183(t *testing.T){ do(192, r("A",183), r("\x09", 9), t)}
func Test192x184(t *testing.T){ do(192, r("A",184), r("\x08", 8), t)}
func Test192x185(t *testing.T){ do(192, r("A",185), r("\x07", 7), t)}
func Test192x186(t *testing.T){ do(192, r("A",186), r("\x06", 6), t)}
func Test192x187(t *testing.T){ do(192, r("A",187), r("\x05", 5), t)}
func Test192x188(t *testing.T){ do(192, r("A",188), r("\x04", 4), t)}
func Test192x189(t *testing.T){ do(192, r("A",189), r("\x03", 3), t)}
func Test192x190(t *testing.T){ do(192, r("A",190), r("\x02", 2), t)}
func Test192x191(t *testing.T){ do(192, r("A",191), r("\x01", 1), t)}
func Test192x192(t *testing.T){ do(192, r("A",192), r("\x00",192), t)}
func Test192x193(t *testing.T){ do(192, r("A",193), r("\xbf",191), t)}
func Test192x194(t *testing.T){ do(192, r("A",194), r("\xbe",190), t)}
func Test192x195(t *testing.T){ do(192, r("A",195), r("\xbd",189), t)}
func Test192x196(t *testing.T){ do(192, r("A",196), r("\xbc",188), t)}
func Test192x197(t *testing.T){ do(192, r("A",197), r("\xbb",187), t)}
func Test192x198(t *testing.T){ do(192, r("A",198), r("\xba",186), t)}
func Test192x199(t *testing.T){ do(192, r("A",199), r("\xb9",185), t)}
func Test192x200(t *testing.T){ do(192, r("A",200), r("\xb8",184), t)}
func Test192x201(t *testing.T){ do(192, r("A",201), r("\xb7",183), t)}
func Test192x202(t *testing.T){ do(192, r("A",202), r("\xb6",182), t)}
func Test192x203(t *testing.T){ do(192, r("A",203), r("\xb5",181), t)}
func Test192x204(t *testing.T){ do(192, r("A",204), r("\xb4",180), t)}
func Test192x205(t *testing.T){ do(192, r("A",205), r("\xb3",179), t)}
func Test192x206(t *testing.T){ do(192, r("A",206), r("\xb2",178), t)}
func Test192x207(t *testing.T){ do(192, r("A",207), r("\xb1",177), t)}
func Test192x208(t *testing.T){ do(192, r("A",208), r("\xb0",176), t)}
func Test192x209(t *testing.T){ do(192, r("A",209), r("\xaf",175), t)}
func Test192x210(t *testing.T){ do(192, r("A",210), r("\xae",174), t)}
func Test192x211(t *testing.T){ do(192, r("A",211), r("\xad",173), t)}
func Test192x212(t *testing.T){ do(192, r("A",212), r("\xac",172), t)}
func Test192x213(t *testing.T){ do(192, r("A",213), r("\xab",171), t)}
func Test192x214(t *testing.T){ do(192, r("A",214), r("\xaa",170), t)}
func Test192x215(t *testing.T){ do(192, r("A",215), r("\xa9",169), t)}
func Test192x216(t *testing.T){ do(192, r("A",216), r("\xa8",168), t)}
func Test192x217(t *testing.T){ do(192, r("A",217), r("\xa7",167), t)}
func Test192x218(t *testing.T){ do(192, r("A",218), r("\xa6",166), t)}
func Test192x219(t *testing.T){ do(192, r("A",219), r("\xa5",165), t)}
func Test192x220(t *testing.T){ do(192, r("A",220), r("\xa4",164), t)}
func Test192x221(t *testing.T){ do(192, r("A",221), r("\xa3",163), t)}
func Test192x222(t *testing.T){ do(192, r("A",222), r("\xa2",162), t)}
func Test192x223(t *testing.T){ do(192, r("A",223), r("\xa1",161), t)}
func Test192x224(t *testing.T){ do(192, r("A",224), r("\xa0",160), t)}
func Test192x225(t *testing.T){ do(192, r("A",225), r("\x9f",159), t)}
func Test192x226(t *testing.T){ do(192, r("A",226), r("\x9e",158), t)}
func Test192x227(t *testing.T){ do(192, r("A",227), r("\x9d",157), t)}
func Test192x228(t *testing.T){ do(192, r("A",228), r("\x9c",156), t)}
func Test192x229(t *testing.T){ do(192, r("A",229), r("\x9b",155), t)}
func Test192x230(t *testing.T){ do(192, r("A",230), r("\x9a",154), t)}
func Test192x231(t *testing.T){ do(192, r("A",231), r("\x99",153), t)}
func Test192x232(t *testing.T){ do(192, r("A",232), r("\x98",152), t)}
func Test192x233(t *testing.T){ do(192, r("A",233), r("\x97",151), t)}
func Test192x234(t *testing.T){ do(192, r("A",234), r("\x96",150), t)}
func Test192x235(t *testing.T){ do(192, r("A",235), r("\x95",149), t)}
func Test192x236(t *testing.T){ do(192, r("A",236), r("\x94",148), t)}
func Test192x237(t *testing.T){ do(192, r("A",237), r("\x93",147), t)}
func Test192x238(t *testing.T){ do(192, r("A",238), r("\x92",146), t)}
func Test192x239(t *testing.T){ do(192, r("A",239), r("\x91",145), t)}
func Test192x240(t *testing.T){ do(192, r("A",240), r("\x90",144), t)}
func Test192x241(t *testing.T){ do(192, r("A",241), r("\x8f",143), t)}
func Test192x242(t *testing.T){ do(192, r("A",242), r("\x8e",142), t)}
func Test192x243(t *testing.T){ do(192, r("A",243), r("\x8d",141), t)}
func Test192x244(t *testing.T){ do(192, r("A",244), r("\x8c",140), t)}
func Test192x245(t *testing.T){ do(192, r("A",245), r("\x8b",139), t)}
func Test192x246(t *testing.T){ do(192, r("A",246), r("\x8a",138), t)}
func Test192x247(t *testing.T){ do(192, r("A",247), r("\x89",137), t)}
func Test192x248(t *testing.T){ do(192, r("A",248), r("\x88",136), t)}
func Test192x249(t *testing.T){ do(192, r("A",249), r("\x87",135), t)}
func Test192x250(t *testing.T){ do(192, r("A",250), r("\x86",134), t)}
func Test192x251(t *testing.T){ do(192, r("A",251), r("\x85",133), t)}
func Test192x252(t *testing.T){ do(192, r("A",252), r("\x84",132), t)}
func Test192x253(t *testing.T){ do(192, r("A",253), r("\x83",131), t)}
func Test192x254(t *testing.T){ do(192, r("A",254), r("\x82",130), t)}
func Test192x255(t *testing.T){ do(192, r("A",255), r("\x81",129), t)}
func Test240x000(t *testing.T){ do(240, r("A", 0), r("\x00",240), t)}
func Test240x001(t *testing.T){ do(240, r("A", 1), r("\xef",239), t)}
func Test240x002(t *testing.T){ do(240, r("A", 2), r("\xee",238), t)}
func Test240x003(t *testing.T){ do(240, r("A", 3), r("\xed",237), t)}
func Test240x004(t *testing.T){ do(240, r("A", 4), r("\xec",236), t)}
func Test240x005(t *testing.T){ do(240, r("A", 5), r("\xeb",235), t)}
func Test240x006(t *testing.T){ do(240, r("A", 6), r("\xea",234), t)}
func Test240x007(t *testing.T){ do(240, r("A", 7), r("\xe9",233), t)}
func Test240x008(t *testing.T){ do(240, r("A", 8), r("\xe8",232), t)}
func Test240x009(t *testing.T){ do(240, r("A", 9), r("\xe7",231), t)}
func Test240x010(t *testing.T){ do(240, r("A",10), r("\xe6",230), t)}
func Test240x011(t *testing.T){ do(240, r("A",11), r("\xe5",229), t)}
func Test240x012(t *testing.T){ do(240, r("A",12), r("\xe4",228), t)}
func Test240x013(t *testing.T){ do(240, r("A",13), r("\xe3",227), t)}
func Test240x014(t *testing.T){ do(240, r("A",14), r("\xe2",226), t)}
func Test240x015(t *testing.T){ do(240, r("A",15), r("\xe1",225), t)}
func Test240x016(t *testing.T){ do(240, r("A",16), r("\xe0",224), t)}
func Test240x017(t *testing.T){ do(240, r("A",17), r("\xdf",223), t)}
func Test240x018(t *testing.T){ do(240, r("A",18), r("\xde",222), t)}
func Test240x019(t *testing.T){ do(240, r("A",19), r("\xdd",221), t)}
func Test240x020(t *testing.T){ do(240, r("A",20), r("\xdc",220), t)}
func Test240x021(t *testing.T){ do(240, r("A",21), r("\xdb",219), t)}
func Test240x022(t *testing.T){ do(240, r("A",22), r("\xda",218), t)}
func Test240x023(t *testing.T){ do(240, r("A",23), r("\xd9",217), t)}
func Test240x024(t *testing.T){ do(240, r("A",24), r("\xd8",216), t)}
func Test240x025(t *testing.T){ do(240, r("A",25), r("\xd7",215), t)}
func Test240x026(t *testing.T){ do(240, r("A",26), r("\xd6",214), t)}
func Test240x027(t *testing.T){ do(240, r("A",27), r("\xd5",213), t)}
func Test240x028(t *testing.T){ do(240, r("A",28), r("\xd4",212), t)}
func Test240x029(t *testing.T){ do(240, r("A",29), r("\xd3",211), t)}
func Test240x030(t *testing.T){ do(240, r("A",30), r("\xd2",210), t)}
func Test240x031(t *testing.T){ do(240, r("A",31), r("\xd1",209), t)}
func Test240x032(t *testing.T){ do(240, r("A",32), r("\xd0",208), t)}
func Test240x033(t *testing.T){ do(240, r("A",33), r("\xcf",207), t)}
func Test240x034(t *testing.T){ do(240, r("A",34), r("\xce",206), t)}
func Test240x035(t *testing.T){ do(240, r("A",35), r("\xcd",205), t)}
func Test240x036(t *testing.T){ do(240, r("A",36), r("\xcc",204), t)}
func Test240x037(t *testing.T){ do(240, r("A",37), r("\xcb",203), t)}
func Test240x038(t *testing.T){ do(240, r("A",38), r("\xca",202), t)}
func Test240x039(t *testing.T){ do(240, r("A",39), r("\xc9",201), t)}
func Test240x040(t *testing.T){ do(240, r("A",40), r("\xc8",200), t)}
func Test240x041(t *testing.T){ do(240, r("A",41), r("\xc7",199), t)}
func Test240x042(t *testing.T){ do(240, r("A",42), r("\xc6",198), t)}
func Test240x043(t *testing.T){ do(240, r("A",43), r("\xc5",197), t)}
func Test240x044(t *testing.T){ do(240, r("A",44), r("\xc4",196), t)}
func Test240x045(t *testing.T){ do(240, r("A",45), r("\xc3",195), t)}
func Test240x046(t *testing.T){ do(240, r("A",46), r("\xc2",194), t)}
func Test240x047(t *testing.T){ do(240, r("A",47), r("\xc1",193), t)}
func Test240x048(t *testing.T){ do(240, r("A",48), r("\xc0",192), t)}
func Test240x049(t *testing.T){ do(240, r("A",49), r("\xbf",191), t)}
func Test240x050(t *testing.T){ do(240, r("A",50), r("\xbe",190), t)}
func Test240x051(t *testing.T){ do(240, r("A",51), r("\xbd",189), t)}
func Test240x052(t *testing.T){ do(240, r("A",52), r("\xbc",188), t)}
func Test240x053(t *testing.T){ do(240, r("A",53), r("\xbb",187), t)}
func Test240x054(t *testing.T){ do(240, r("A",54), r("\xba",186), t)}
func Test240x055(t *testing.T){ do(240, r("A",55), r("\xb9",185), t)}
func Test240x056(t *testing.T){ do(240, r("A",56), r("\xb8",184), t)}
func Test240x057(t *testing.T){ do(240, r("A",57), r("\xb7",183), t)}
func Test240x058(t *testing.T){ do(240, r("A",58), r("\xb6",182), t)}
func Test240x059(t *testing.T){ do(240, r("A",59), r("\xb5",181), t)}
func Test240x060(t *testing.T){ do(240, r("A",60), r("\xb4",180), t)}
func Test240x061(t *testing.T){ do(240, r("A",61), r("\xb3",179), t)}
func Test240x062(t *testing.T){ do(240, r("A",62), r("\xb2",178), t)}
func Test240x063(t *testing.T){ do(240, r("A",63), r("\xb1",177), t)}
func Test240x064(t *testing.T){ do(240, r("A",64), r("\xb0",176), t)}
func Test240x065(t *testing.T){ do(240, r("A",65), r("\xaf",175), t)}
func Test240x066(t *testing.T){ do(240, r("A",66), r("\xae",174), t)}
func Test240x067(t *testing.T){ do(240, r("A",67), r("\xad",173), t)}
func Test240x068(t *testing.T){ do(240, r("A",68), r("\xac",172), t)}
func Test240x069(t *testing.T){ do(240, r("A",69), r("\xab",171), t)}
func Test240x070(t *testing.T){ do(240, r("A",70), r("\xaa",170), t)}
func Test240x071(t *testing.T){ do(240, r("A",71), r("\xa9",169), t)}
func Test240x072(t *testing.T){ do(240, r("A",72), r("\xa8",168), t)}
func Test240x073(t *testing.T){ do(240, r("A",73), r("\xa7",167), t)}
func Test240x074(t *testing.T){ do(240, r("A",74), r("\xa6",166), t)}
func Test240x075(t *testing.T){ do(240, r("A",75), r("\xa5",165), t)}
func Test240x076(t *testing.T){ do(240, r("A",76), r("\xa4",164), t)}
func Test240x077(t *testing.T){ do(240, r("A",77), r("\xa3",163), t)}
func Test240x078(t *testing.T){ do(240, r("A",78), r("\xa2",162), t)}
func Test240x079(t *testing.T){ do(240, r("A",79), r("\xa1",161), t)}
func Test240x080(t *testing.T){ do(240, r("A",80), r("\xa0",160), t)}
func Test240x081(t *testing.T){ do(240, r("A",81), r("\x9f",159), t)}
func Test240x082(t *testing.T){ do(240, r("A",82), r("\x9e",158), t)}
func Test240x083(t *testing.T){ do(240, r("A",83), r("\x9d",157), t)}
func Test240x084(t *testing.T){ do(240, r("A",84), r("\x9c",156), t)}
func Test240x085(t *testing.T){ do(240, r("A",85), r("\x9b",155), t)}
func Test240x086(t *testing.T){ do(240, r("A",86), r("\x9a",154), t)}
func Test240x087(t *testing.T){ do(240, r("A",87), r("\x99",153), t)}
func Test240x088(t *testing.T){ do(240, r("A",88), r("\x98",152), t)}
func Test240x089(t *testing.T){ do(240, r("A",89), r("\x97",151), t)}
func Test240x090(t *testing.T){ do(240, r("A",90), r("\x96",150), t)}
func Test240x091(t *testing.T){ do(240, r("A",91), r("\x95",149), t)}
func Test240x092(t *testing.T){ do(240, r("A",92), r("\x94",148), t)}
func Test240x093(t *testing.T){ do(240, r("A",93), r("\x93",147), t)}
func Test240x094(t *testing.T){ do(240, r("A",94), r("\x92",146), t)}
func Test240x095(t *testing.T){ do(240, r("A",95), r("\x91",145), t)}
func Test240x096(t *testing.T){ do(240, r("A",96), r("\x90",144), t)}
func Test240x097(t *testing.T){ do(240, r("A",97), r("\x8f",143), t)}
func Test240x098(t *testing.T){ do(240, r("A",98), r("\x8e",142), t)}
func Test240x099(t *testing.T){ do(240, r("A",99), r("\x8d",141), t)}
func Test240x100(t *testing.T){ do(240, r("A",100), r("\x8c",140), t)}
func Test240x101(t *testing.T){ do(240, r("A",101), r("\x8b",139), t)}
func Test240x102(t *testing.T){ do(240, r("A",102), r("\x8a",138), t)}
func Test240x103(t *testing.T){ do(240, r("A",103), r("\x89",137), t)}
func Test240x104(t *testing.T){ do(240, r("A",104), r("\x88",136), t)}
func Test240x105(t *testing.T){ do(240, r("A",105), r("\x87",135), t)}
func Test240x106(t *testing.T){ do(240, r("A",106), r("\x86",134), t)}
func Test240x107(t *testing.T){ do(240, r("A",107), r("\x85",133), t)}
func Test240x108(t *testing.T){ do(240, r("A",108), r("\x84",132), t)}
func Test240x109(t *testing.T){ do(240, r("A",109), r("\x83",131), t)}
func Test240x110(t *testing.T){ do(240, r("A",110), r("\x82",130), t)}
func Test240x111(t *testing.T){ do(240, r("A",111), r("\x81",129), t)}
func Test240x112(t *testing.T){ do(240, r("A",112), r("\x80",128), t)}
func Test240x113(t *testing.T){ do(240, r("A",113), r("\x7f",127), t)}
func Test240x114(t *testing.T){ do(240, r("A",114), r("\x7e",126), t)}
func Test240x115(t *testing.T){ do(240, r("A",115), r("\x7d",125), t)}
func Test240x116(t *testing.T){ do(240, r("A",116), r("\x7c",124), t)}
func Test240x117(t *testing.T){ do(240, r("A",117), r("\x7b",123), t)}
func Test240x118(t *testing.T){ do(240, r("A",118), r("\x7a",122), t)}
func Test240x119(t *testing.T){ do(240, r("A",119), r("\x79",121), t)}
func Test240x120(t *testing.T){ do(240, r("A",120), r("\x78",120), t)}
func Test240x121(t *testing.T){ do(240, r("A",121), r("\x77",119), t)}
func Test240x122(t *testing.T){ do(240, r("A",122), r("\x76",118), t)}
func Test240x123(t *testing.T){ do(240, r("A",123), r("\x75",117), t)}
func Test240x124(t *testing.T){ do(240, r("A",124), r("\x74",116), t)}
func Test240x125(t *testing.T){ do(240, r("A",125), r("\x73",115), t)}
func Test240x126(t *testing.T){ do(240, r("A",126), r("\x72",114), t)}
func Test240x127(t *testing.T){ do(240, r("A",127), r("\x71",113), t)}
func Test240x128(t *testing.T){ do(240, r("A",128), r("\x70",112), t)}
func Test240x129(t *testing.T){ do(240, r("A",129), r("\x6f",111), t)}
func Test240x130(t *testing.T){ do(240, r("A",130), r("\x6e",110), t)}
func Test240x131(t *testing.T){ do(240, r("A",131), r("\x6d",109), t)}
func Test240x132(t *testing.T){ do(240, r("A",132), r("\x6c",108), t)}
func Test240x133(t *testing.T){ do(240, r("A",133), r("\x6b",107), t)}
func Test240x134(t *testing.T){ do(240, r("A",134), r("\x6a",106), t)}
func Test240x135(t *testing.T){ do(240, r("A",135), r("\x69",105), t)}
func Test240x136(t *testing.T){ do(240, r("A",136), r("\x68",104), t)}
func Test240x137(t *testing.T){ do(240, r("A",137), r("\x67",103), t)}
func Test240x138(t *testing.T){ do(240, r("A",138), r("\x66",102), t)}
func Test240x139(t *testing.T){ do(240, r("A",139), r("\x65",101), t)}
func Test240x140(t *testing.T){ do(240, r("A",140), r("\x64",100), t)}
func Test240x141(t *testing.T){ do(240, r("A",141), r("\x63",99), t)}
func Test240x142(t *testing.T){ do(240, r("A",142), r("\x62",98), t)}
func Test240x143(t *testing.T){ do(240, r("A",143), r("\x61",97), t)}
func Test240x144(t *testing.T){ do(240, r("A",144), r("\x60",96), t)}
func Test240x145(t *testing.T){ do(240, r("A",145), r("\x5f",95), t)}
func Test240x146(t *testing.T){ do(240, r("A",146), r("\x5e",94), t)}
func Test240x147(t *testing.T){ do(240, r("A",147), r("\x5d",93), t)}
func Test240x148(t *testing.T){ do(240, r("A",148), r("\x5c",92), t)}
func Test240x149(t *testing.T){ do(240, r("A",149), r("\x5b",91), t)}
func Test240x150(t *testing.T){ do(240, r("A",150), r("\x5a",90), t)}
func Test240x151(t *testing.T){ do(240, r("A",151), r("\x59",89), t)}
func Test240x152(t *testing.T){ do(240, r("A",152), r("\x58",88), t)}
func Test240x153(t *testing.T){ do(240, r("A",153), r("\x57",87), t)}
func Test240x154(t *testing.T){ do(240, r("A",154), r("\x56",86), t)}
func Test240x155(t *testing.T){ do(240, r("A",155), r("\x55",85), t)}
func Test240x156(t *testing.T){ do(240, r("A",156), r("\x54",84), t)}
func Test240x157(t *testing.T){ do(240, r("A",157), r("\x53",83), t)}
func Test240x158(t *testing.T){ do(240, r("A",158), r("\x52",82), t)}
func Test240x159(t *testing.T){ do(240, r("A",159), r("\x51",81), t)}
func Test240x160(t *testing.T){ do(240, r("A",160), r("\x50",80), t)}
func Test240x161(t *testing.T){ do(240, r("A",161), r("\x4f",79), t)}
func Test240x162(t *testing.T){ do(240, r("A",162), r("\x4e",78), t)}
func Test240x163(t *testing.T){ do(240, r("A",163), r("\x4d",77), t)}
func Test240x164(t *testing.T){ do(240, r("A",164), r("\x4c",76), t)}
func Test240x165(t *testing.T){ do(240, r("A",165), r("\x4b",75), t)}
func Test240x166(t *testing.T){ do(240, r("A",166), r("\x4a",74), t)}
func Test240x167(t *testing.T){ do(240, r("A",167), r("\x49",73), t)}
func Test240x168(t *testing.T){ do(240, r("A",168), r("\x48",72), t)}
func Test240x169(t *testing.T){ do(240, r("A",169), r("\x47",71), t)}
func Test240x170(t *testing.T){ do(240, r("A",170), r("\x46",70), t)}
func Test240x171(t *testing.T){ do(240, r("A",171), r("\x45",69), t)}
func Test240x172(t *testing.T){ do(240, r("A",172), r("\x44",68), t)}
func Test240x173(t *testing.T){ do(240, r("A",173), r("\x43",67), t)}
func Test240x174(t *testing.T){ do(240, r("A",174), r("\x42",66), t)}
func Test240x175(t *testing.T){ do(240, r("A",175), r("\x41",65), t)}
func Test240x176(t *testing.T){ do(240, r("A",176), r("\x40",64), t)}
func Test240x177(t *testing.T){ do(240, r("A",177), r("\x3f",63), t)}
func Test240x178(t *testing.T){ do(240, r("A",178), r("\x3e",62), t)}
func Test240x179(t *testing.T){ do(240, r("A",179), r("\x3d",61), t)}
func Test240x180(t *testing.T){ do(240, r("A",180), r("\x3c",60), t)}
func Test240x181(t *testing.T){ do(240, r("A",181), r("\x3b",59), t)}
func Test240x182(t *testing.T){ do(240, r("A",182), r("\x3a",58), t)}
func Test240x183(t *testing.T){ do(240, r("A",183), r("\x39",57), t)}
func Test240x184(t *testing.T){ do(240, r("A",184), r("\x38",56), t)}
func Test240x185(t *testing.T){ do(240, r("A",185), r("\x37",55), t)}
func Test240x186(t *testing.T){ do(240, r("A",186), r("\x36",54), t)}
func Test240x187(t *testing.T){ do(240, r("A",187), r("\x35",53), t)}
func Test240x188(t *testing.T){ do(240, r("A",188), r("\x34",52), t)}
func Test240x189(t *testing.T){ do(240, r("A",189), r("\x33",51), t)}
func Test240x190(t *testing.T){ do(240, r("A",190), r("\x32",50), t)}
func Test240x191(t *testing.T){ do(240, r("A",191), r("\x31",49), t)}
func Test240x192(t *testing.T){ do(240, r("A",192), r("\x30",48), t)}
func Test240x193(t *testing.T){ do(240, r("A",193), r("\x2f",47), t)}
func Test240x194(t *testing.T){ do(240, r("A",194), r("\x2e",46), t)}
func Test240x195(t *testing.T){ do(240, r("A",195), r("\x2d",45), t)}
func Test240x196(t *testing.T){ do(240, r("A",196), r("\x2c",44), t)}
func Test240x197(t *testing.T){ do(240, r("A",197), r("\x2b",43), t)}
func Test240x198(t *testing.T){ do(240, r("A",198), r("\x2a",42), t)}
func Test240x199(t *testing.T){ do(240, r("A",199), r("\x29",41), t)}
func Test240x200(t *testing.T){ do(240, r("A",200), r("\x28",40), t)}
func Test240x201(t *testing.T){ do(240, r("A",201), r("\x27",39), t)}
func Test240x202(t *testing.T){ do(240, r("A",202), r("\x26",38), t)}
func Test240x203(t *testing.T){ do(240, r("A",203), r("\x25",37), t)}
func Test240x204(t *testing.T){ do(240, r("A",204), r("\x24",36), t)}
func Test240x205(t *testing.T){ do(240, r("A",205), r("\x23",35), t)}
func Test240x206(t *testing.T){ do(240, r("A",206), r("\x22",34), t)}
func Test240x207(t *testing.T){ do(240, r("A",207), r("\x21",33), t)}
func Test240x208(t *testing.T){ do(240, r("A",208), r("\x20",32), t)}
func Test240x209(t *testing.T){ do(240, r("A",209), r("\x1f",31), t)}
func Test240x210(t *testing.T){ do(240, r("A",210), r("\x1e",30), t)}
func Test240x211(t *testing.T){ do(240, r("A",211), r("\x1d",29), t)}
func Test240x212(t *testing.T){ do(240, r("A",212), r("\x1c",28), t)}
func Test240x213(t *testing.T){ do(240, r("A",213), r("\x1b",27), t)}
func Test240x214(t *testing.T){ do(240, r("A",214), r("\x1a",26), t)}
func Test240x215(t *testing.T){ do(240, r("A",215), r("\x19",25), t)}
func Test240x216(t *testing.T){ do(240, r("A",216), r("\x18",24), t)}
func Test240x217(t *testing.T){ do(240, r("A",217), r("\x17",23), t)}
func Test240x218(t *testing.T){ do(240, r("A",218), r("\x16",22), t)}
func Test240x219(t *testing.T){ do(240, r("A",219), r("\x15",21), t)}
func Test240x220(t *testing.T){ do(240, r("A",220), r("\x14",20), t)}
func Test240x221(t *testing.T){ do(240, r("A",221), r("\x13",19), t)}
func Test240x222(t *testing.T){ do(240, r("A",222), r("\x12",18), t)}
func Test240x223(t *testing.T){ do(240, r("A",223), r("\x11",17), t)}
func Test240x224(t *testing.T){ do(240, r("A",224), r("\x10",16), t)}
func Test240x225(t *testing.T){ do(240, r("A",225), r("\x0f",15), t)}
func Test240x226(t *testing.T){ do(240, r("A",226), r("\x0e",14), t)}
func Test240x227(t *testing.T){ do(240, r("A",227), r("\x0d",13), t)}
func Test240x228(t *testing.T){ do(240, r("A",228), r("\x0c",12), t)}
func Test240x229(t *testing.T){ do(240, r("A",229), r("\x0b",11), t)}
func Test240x230(t *testing.T){ do(240, r("A",230), r("\x0a",10), t)}
func Test240x231(t *testing.T){ do(240, r("A",231), r("\x09", 9), t)}
func Test240x232(t *testing.T){ do(240, r("A",232), r("\x08", 8), t)}
func Test240x233(t *testing.T){ do(240, r("A",233), r("\x07", 7), t)}
func Test240x234(t *testing.T){ do(240, r("A",234), r("\x06", 6), t)}
func Test240x235(t *testing.T){ do(240, r("A",235), r("\x05", 5), t)}
func Test240x236(t *testing.T){ do(240, r("A",236), r("\x04", 4), t)}
func Test240x237(t *testing.T){ do(240, r("A",237), r("\x03", 3), t)}
func Test240x238(t *testing.T){ do(240, r("A",238), r("\x02", 2), t)}
func Test240x239(t *testing.T){ do(240, r("A",239), r("\x01", 1), t)}
func Test240x240(t *testing.T){ do(240, r("A",240), r("\x00",240), t)}
func Test240x241(t *testing.T){ do(240, r("A",241), r("\xef",239), t)}
func Test240x242(t *testing.T){ do(240, r("A",242), r("\xee",238), t)}
func Test240x243(t *testing.T){ do(240, r("A",243), r("\xed",237), t)}
func Test240x244(t *testing.T){ do(240, r("A",244), r("\xec",236), t)}
func Test240x245(t *testing.T){ do(240, r("A",245), r("\xeb",235), t)}
func Test240x246(t *testing.T){ do(240, r("A",246), r("\xea",234), t)}
func Test240x247(t *testing.T){ do(240, r("A",247), r("\xe9",233), t)}
func Test240x248(t *testing.T){ do(240, r("A",248), r("\xe8",232), t)}
func Test240x249(t *testing.T){ do(240, r("A",249), r("\xe7",231), t)}
func Test240x250(t *testing.T){ do(240, r("A",250), r("\xe6",230), t)}
func Test240x251(t *testing.T){ do(240, r("A",251), r("\xe5",229), t)}
func Test240x252(t *testing.T){ do(240, r("A",252), r("\xe4",228), t)}
func Test240x253(t *testing.T){ do(240, r("A",253), r("\xe3",227), t)}
func Test240x254(t *testing.T){ do(240, r("A",254), r("\xe2",226), t)}
func Test240x255(t *testing.T){ do(240, r("A",255), r("\xe1",225), t)}
func Test248x000(t *testing.T){ do(248, r("A", 0), r("\x00",248), t)}
func Test248x001(t *testing.T){ do(248, r("A", 1), r("\xf7",247), t)}
func Test248x002(t *testing.T){ do(248, r("A", 2), r("\xf6",246), t)}
func Test248x003(t *testing.T){ do(248, r("A", 3), r("\xf5",245), t)}
func Test248x004(t *testing.T){ do(248, r("A", 4), r("\xf4",244), t)}
func Test248x005(t *testing.T){ do(248, r("A", 5), r("\xf3",243), t)}
func Test248x006(t *testing.T){ do(248, r("A", 6), r("\xf2",242), t)}
func Test248x007(t *testing.T){ do(248, r("A", 7), r("\xf1",241), t)}
func Test248x008(t *testing.T){ do(248, r("A", 8), r("\xf0",240), t)}
func Test248x009(t *testing.T){ do(248, r("A", 9), r("\xef",239), t)}
func Test248x010(t *testing.T){ do(248, r("A",10), r("\xee",238), t)}
func Test248x011(t *testing.T){ do(248, r("A",11), r("\xed",237), t)}
func Test248x012(t *testing.T){ do(248, r("A",12), r("\xec",236), t)}
func Test248x013(t *testing.T){ do(248, r("A",13), r("\xeb",235), t)}
func Test248x014(t *testing.T){ do(248, r("A",14), r("\xea",234), t)}
func Test248x015(t *testing.T){ do(248, r("A",15), r("\xe9",233), t)}
func Test248x016(t *testing.T){ do(248, r("A",16), r("\xe8",232), t)}
func Test248x017(t *testing.T){ do(248, r("A",17), r("\xe7",231), t)}
func Test248x018(t *testing.T){ do(248, r("A",18), r("\xe6",230), t)}
func Test248x019(t *testing.T){ do(248, r("A",19), r("\xe5",229), t)}
func Test248x020(t *testing.T){ do(248, r("A",20), r("\xe4",228), t)}
func Test248x021(t *testing.T){ do(248, r("A",21), r("\xe3",227), t)}
func Test248x022(t *testing.T){ do(248, r("A",22), r("\xe2",226), t)}
func Test248x023(t *testing.T){ do(248, r("A",23), r("\xe1",225), t)}
func Test248x024(t *testing.T){ do(248, r("A",24), r("\xe0",224), t)}
func Test248x025(t *testing.T){ do(248, r("A",25), r("\xdf",223), t)}
func Test248x026(t *testing.T){ do(248, r("A",26), r("\xde",222), t)}
func Test248x027(t *testing.T){ do(248, r("A",27), r("\xdd",221), t)}
func Test248x028(t *testing.T){ do(248, r("A",28), r("\xdc",220), t)}
func Test248x029(t *testing.T){ do(248, r("A",29), r("\xdb",219), t)}
func Test248x030(t *testing.T){ do(248, r("A",30), r("\xda",218), t)}
func Test248x031(t *testing.T){ do(248, r("A",31), r("\xd9",217), t)}
func Test248x032(t *testing.T){ do(248, r("A",32), r("\xd8",216), t)}
func Test248x033(t *testing.T){ do(248, r("A",33), r("\xd7",215), t)}
func Test248x034(t *testing.T){ do(248, r("A",34), r("\xd6",214), t)}
func Test248x035(t *testing.T){ do(248, r("A",35), r("\xd5",213), t)}
func Test248x036(t *testing.T){ do(248, r("A",36), r("\xd4",212), t)}
func Test248x037(t *testing.T){ do(248, r("A",37), r("\xd3",211), t)}
func Test248x038(t *testing.T){ do(248, r("A",38), r("\xd2",210), t)}
func Test248x039(t *testing.T){ do(248, r("A",39), r("\xd1",209), t)}
func Test248x040(t *testing.T){ do(248, r("A",40), r("\xd0",208), t)}
func Test248x041(t *testing.T){ do(248, r("A",41), r("\xcf",207), t)}
func Test248x042(t *testing.T){ do(248, r("A",42), r("\xce",206), t)}
func Test248x043(t *testing.T){ do(248, r("A",43), r("\xcd",205), t)}
func Test248x044(t *testing.T){ do(248, r("A",44), r("\xcc",204), t)}
func Test248x045(t *testing.T){ do(248, r("A",45), r("\xcb",203), t)}
func Test248x046(t *testing.T){ do(248, r("A",46), r("\xca",202), t)}
func Test248x047(t *testing.T){ do(248, r("A",47), r("\xc9",201), t)}
func Test248x048(t *testing.T){ do(248, r("A",48), r("\xc8",200), t)}
func Test248x049(t *testing.T){ do(248, r("A",49), r("\xc7",199), t)}
func Test248x050(t *testing.T){ do(248, r("A",50), r("\xc6",198), t)}
func Test248x051(t *testing.T){ do(248, r("A",51), r("\xc5",197), t)}
func Test248x052(t *testing.T){ do(248, r("A",52), r("\xc4",196), t)}
func Test248x053(t *testing.T){ do(248, r("A",53), r("\xc3",195), t)}
func Test248x054(t *testing.T){ do(248, r("A",54), r("\xc2",194), t)}
func Test248x055(t *testing.T){ do(248, r("A",55), r("\xc1",193), t)}
func Test248x056(t *testing.T){ do(248, r("A",56), r("\xc0",192), t)}
func Test248x057(t *testing.T){ do(248, r("A",57), r("\xbf",191), t)}
func Test248x058(t *testing.T){ do(248, r("A",58), r("\xbe",190), t)}
func Test248x059(t *testing.T){ do(248, r("A",59), r("\xbd",189), t)}
func Test248x060(t *testing.T){ do(248, r("A",60), r("\xbc",188), t)}
func Test248x061(t *testing.T){ do(248, r("A",61), r("\xbb",187), t)}
func Test248x062(t *testing.T){ do(248, r("A",62), r("\xba",186), t)}
func Test248x063(t *testing.T){ do(248, r("A",63), r("\xb9",185), t)}
func Test248x064(t *testing.T){ do(248, r("A",64), r("\xb8",184), t)}
func Test248x065(t *testing.T){ do(248, r("A",65), r("\xb7",183), t)}
func Test248x066(t *testing.T){ do(248, r("A",66), r("\xb6",182), t)}
func Test248x067(t *testing.T){ do(248, r("A",67), r("\xb5",181), t)}
func Test248x068(t *testing.T){ do(248, r("A",68), r("\xb4",180), t)}
func Test248x069(t *testing.T){ do(248, r("A",69), r("\xb3",179), t)}
func Test248x070(t *testing.T){ do(248, r("A",70), r("\xb2",178), t)}
func Test248x071(t *testing.T){ do(248, r("A",71), r("\xb1",177), t)}
func Test248x072(t *testing.T){ do(248, r("A",72), r("\xb0",176), t)}
func Test248x073(t *testing.T){ do(248, r("A",73), r("\xaf",175), t)}
func Test248x074(t *testing.T){ do(248, r("A",74), r("\xae",174), t)}
func Test248x075(t *testing.T){ do(248, r("A",75), r("\xad",173), t)}
func Test248x076(t *testing.T){ do(248, r("A",76), r("\xac",172), t)}
func Test248x077(t *testing.T){ do(248, r("A",77), r("\xab",171), t)}
func Test248x078(t *testing.T){ do(248, r("A",78), r("\xaa",170), t)}
func Test248x079(t *testing.T){ do(248, r("A",79), r("\xa9",169), t)}
func Test248x080(t *testing.T){ do(248, r("A",80), r("\xa8",168), t)}
func Test248x081(t *testing.T){ do(248, r("A",81), r("\xa7",167), t)}
func Test248x082(t *testing.T){ do(248, r("A",82), r("\xa6",166), t)}
func Test248x083(t *testing.T){ do(248, r("A",83), r("\xa5",165), t)}
func Test248x084(t *testing.T){ do(248, r("A",84), r("\xa4",164), t)}
func Test248x085(t *testing.T){ do(248, r("A",85), r("\xa3",163), t)}
func Test248x086(t *testing.T){ do(248, r("A",86), r("\xa2",162), t)}
func Test248x087(t *testing.T){ do(248, r("A",87), r("\xa1",161), t)}
func Test248x088(t *testing.T){ do(248, r("A",88), r("\xa0",160), t)}
func Test248x089(t *testing.T){ do(248, r("A",89), r("\x9f",159), t)}
func Test248x090(t *testing.T){ do(248, r("A",90), r("\x9e",158), t)}
func Test248x091(t *testing.T){ do(248, r("A",91), r("\x9d",157), t)}
func Test248x092(t *testing.T){ do(248, r("A",92), r("\x9c",156), t)}
func Test248x093(t *testing.T){ do(248, r("A",93), r("\x9b",155), t)}
func Test248x094(t *testing.T){ do(248, r("A",94), r("\x9a",154), t)}
func Test248x095(t *testing.T){ do(248, r("A",95), r("\x99",153), t)}
func Test248x096(t *testing.T){ do(248, r("A",96), r("\x98",152), t)}
func Test248x097(t *testing.T){ do(248, r("A",97), r("\x97",151), t)}
func Test248x098(t *testing.T){ do(248, r("A",98), r("\x96",150), t)}
func Test248x099(t *testing.T){ do(248, r("A",99), r("\x95",149), t)}
func Test248x100(t *testing.T){ do(248, r("A",100), r("\x94",148), t)}
func Test248x101(t *testing.T){ do(248, r("A",101), r("\x93",147), t)}
func Test248x102(t *testing.T){ do(248, r("A",102), r("\x92",146), t)}
func Test248x103(t *testing.T){ do(248, r("A",103), r("\x91",145), t)}
func Test248x104(t *testing.T){ do(248, r("A",104), r("\x90",144), t)}
func Test248x105(t *testing.T){ do(248, r("A",105), r("\x8f",143), t)}
func Test248x106(t *testing.T){ do(248, r("A",106), r("\x8e",142), t)}
func Test248x107(t *testing.T){ do(248, r("A",107), r("\x8d",141), t)}
func Test248x108(t *testing.T){ do(248, r("A",108), r("\x8c",140), t)}
func Test248x109(t *testing.T){ do(248, r("A",109), r("\x8b",139), t)}
func Test248x110(t *testing.T){ do(248, r("A",110), r("\x8a",138), t)}
func Test248x111(t *testing.T){ do(248, r("A",111), r("\x89",137), t)}
func Test248x112(t *testing.T){ do(248, r("A",112), r("\x88",136), t)}
func Test248x113(t *testing.T){ do(248, r("A",113), r("\x87",135), t)}
func Test248x114(t *testing.T){ do(248, r("A",114), r("\x86",134), t)}
func Test248x115(t *testing.T){ do(248, r("A",115), r("\x85",133), t)}
func Test248x116(t *testing.T){ do(248, r("A",116), r("\x84",132), t)}
func Test248x117(t *testing.T){ do(248, r("A",117), r("\x83",131), t)}
func Test248x118(t *testing.T){ do(248, r("A",118), r("\x82",130), t)}
func Test248x119(t *testing.T){ do(248, r("A",119), r("\x81",129), t)}
func Test248x120(t *testing.T){ do(248, r("A",120), r("\x80",128), t)}
func Test248x121(t *testing.T){ do(248, r("A",121), r("\x7f",127), t)}
func Test248x122(t *testing.T){ do(248, r("A",122), r("\x7e",126), t)}
func Test248x123(t *testing.T){ do(248, r("A",123), r("\x7d",125), t)}
func Test248x124(t *testing.T){ do(248, r("A",124), r("\x7c",124), t)}
func Test248x125(t *testing.T){ do(248, r("A",125), r("\x7b",123), t)}
func Test248x126(t *testing.T){ do(248, r("A",126), r("\x7a",122), t)}
func Test248x127(t *testing.T){ do(248, r("A",127), r("\x79",121), t)}
func Test248x128(t *testing.T){ do(248, r("A",128), r("\x78",120), t)}
func Test248x129(t *testing.T){ do(248, r("A",129), r("\x77",119), t)}
func Test248x130(t *testing.T){ do(248, r("A",130), r("\x76",118), t)}
func Test248x131(t *testing.T){ do(248, r("A",131), r("\x75",117), t)}
func Test248x132(t *testing.T){ do(248, r("A",132), r("\x74",116), t)}
func Test248x133(t *testing.T){ do(248, r("A",133), r("\x73",115), t)}
func Test248x134(t *testing.T){ do(248, r("A",134), r("\x72",114), t)}
func Test248x135(t *testing.T){ do(248, r("A",135), r("\x71",113), t)}
func Test248x136(t *testing.T){ do(248, r("A",136), r("\x70",112), t)}
func Test248x137(t *testing.T){ do(248, r("A",137), r("\x6f",111), t)}
func Test248x138(t *testing.T){ do(248, r("A",138), r("\x6e",110), t)}
func Test248x139(t *testing.T){ do(248, r("A",139), r("\x6d",109), t)}
func Test248x140(t *testing.T){ do(248, r("A",140), r("\x6c",108), t)}
func Test248x141(t *testing.T){ do(248, r("A",141), r("\x6b",107), t)}
func Test248x142(t *testing.T){ do(248, r("A",142), r("\x6a",106), t)}
func Test248x143(t *testing.T){ do(248, r("A",143), r("\x69",105), t)}
func Test248x144(t *testing.T){ do(248, r("A",144), r("\x68",104), t)}
func Test248x145(t *testing.T){ do(248, r("A",145), r("\x67",103), t)}
func Test248x146(t *testing.T){ do(248, r("A",146), r("\x66",102), t)}
func Test248x147(t *testing.T){ do(248, r("A",147), r("\x65",101), t)}
func Test248x148(t *testing.T){ do(248, r("A",148), r("\x64",100), t)}
func Test248x149(t *testing.T){ do(248, r("A",149), r("\x63",99), t)}
func Test248x150(t *testing.T){ do(248, r("A",150), r("\x62",98), t)}
func Test248x151(t *testing.T){ do(248, r("A",151), r("\x61",97), t)}
func Test248x152(t *testing.T){ do(248, r("A",152), r("\x60",96), t)}
func Test248x153(t *testing.T){ do(248, r("A",153), r("\x5f",95), t)}
func Test248x154(t *testing.T){ do(248, r("A",154), r("\x5e",94), t)}
func Test248x155(t *testing.T){ do(248, r("A",155), r("\x5d",93), t)}
func Test248x156(t *testing.T){ do(248, r("A",156), r("\x5c",92), t)}
func Test248x157(t *testing.T){ do(248, r("A",157), r("\x5b",91), t)}
func Test248x158(t *testing.T){ do(248, r("A",158), r("\x5a",90), t)}
func Test248x159(t *testing.T){ do(248, r("A",159), r("\x59",89), t)}
func Test248x160(t *testing.T){ do(248, r("A",160), r("\x58",88), t)}
func Test248x161(t *testing.T){ do(248, r("A",161), r("\x57",87), t)}
func Test248x162(t *testing.T){ do(248, r("A",162), r("\x56",86), t)}
func Test248x163(t *testing.T){ do(248, r("A",163), r("\x55",85), t)}
func Test248x164(t *testing.T){ do(248, r("A",164), r("\x54",84), t)}
func Test248x165(t *testing.T){ do(248, r("A",165), r("\x53",83), t)}
func Test248x166(t *testing.T){ do(248, r("A",166), r("\x52",82), t)}
func Test248x167(t *testing.T){ do(248, r("A",167), r("\x51",81), t)}
func Test248x168(t *testing.T){ do(248, r("A",168), r("\x50",80), t)}
func Test248x169(t *testing.T){ do(248, r("A",169), r("\x4f",79), t)}
func Test248x170(t *testing.T){ do(248, r("A",170), r("\x4e",78), t)}
func Test248x171(t *testing.T){ do(248, r("A",171), r("\x4d",77), t)}
func Test248x172(t *testing.T){ do(248, r("A",172), r("\x4c",76), t)}
func Test248x173(t *testing.T){ do(248, r("A",173), r("\x4b",75), t)}
func Test248x174(t *testing.T){ do(248, r("A",174), r("\x4a",74), t)}
func Test248x175(t *testing.T){ do(248, r("A",175), r("\x49",73), t)}
func Test248x176(t *testing.T){ do(248, r("A",176), r("\x48",72), t)}
func Test248x177(t *testing.T){ do(248, r("A",177), r("\x47",71), t)}
func Test248x178(t *testing.T){ do(248, r("A",178), r("\x46",70), t)}
func Test248x179(t *testing.T){ do(248, r("A",179), r("\x45",69), t)}
func Test248x180(t *testing.T){ do(248, r("A",180), r("\x44",68), t)}
func Test248x181(t *testing.T){ do(248, r("A",181), r("\x43",67), t)}
func Test248x182(t *testing.T){ do(248, r("A",182), r("\x42",66), t)}
func Test248x183(t *testing.T){ do(248, r("A",183), r("\x41",65), t)}
func Test248x184(t *testing.T){ do(248, r("A",184), r("\x40",64), t)}
func Test248x185(t *testing.T){ do(248, r("A",185), r("\x3f",63), t)}
func Test248x186(t *testing.T){ do(248, r("A",186), r("\x3e",62), t)}
func Test248x187(t *testing.T){ do(248, r("A",187), r("\x3d",61), t)}
func Test248x188(t *testing.T){ do(248, r("A",188), r("\x3c",60), t)}
func Test248x189(t *testing.T){ do(248, r("A",189), r("\x3b",59), t)}
func Test248x190(t *testing.T){ do(248, r("A",190), r("\x3a",58), t)}
func Test248x191(t *testing.T){ do(248, r("A",191), r("\x39",57), t)}
func Test248x192(t *testing.T){ do(248, r("A",192), r("\x38",56), t)}
func Test248x193(t *testing.T){ do(248, r("A",193), r("\x37",55), t)}
func Test248x194(t *testing.T){ do(248, r("A",194), r("\x36",54), t)}
func Test248x195(t *testing.T){ do(248, r("A",195), r("\x35",53), t)}
func Test248x196(t *testing.T){ do(248, r("A",196), r("\x34",52), t)}
func Test248x197(t *testing.T){ do(248, r("A",197), r("\x33",51), t)}
func Test248x198(t *testing.T){ do(248, r("A",198), r("\x32",50), t)}
func Test248x199(t *testing.T){ do(248, r("A",199), r("\x31",49), t)}
func Test248x200(t *testing.T){ do(248, r("A",200), r("\x30",48), t)}
func Test248x201(t *testing.T){ do(248, r("A",201), r("\x2f",47), t)}
func Test248x202(t *testing.T){ do(248, r("A",202), r("\x2e",46), t)}
func Test248x203(t *testing.T){ do(248, r("A",203), r("\x2d",45), t)}
func Test248x204(t *testing.T){ do(248, r("A",204), r("\x2c",44), t)}
func Test248x205(t *testing.T){ do(248, r("A",205), r("\x2b",43), t)}
func Test248x206(t *testing.T){ do(248, r("A",206), r("\x2a",42), t)}
func Test248x207(t *testing.T){ do(248, r("A",207), r("\x29",41), t)}
func Test248x208(t *testing.T){ do(248, r("A",208), r("\x28",40), t)}
func Test248x209(t *testing.T){ do(248, r("A",209), r("\x27",39), t)}
func Test248x210(t *testing.T){ do(248, r("A",210), r("\x26",38), t)}
func Test248x211(t *testing.T){ do(248, r("A",211), r("\x25",37), t)}
func Test248x212(t *testing.T){ do(248, r("A",212), r("\x24",36), t)}
func Test248x213(t *testing.T){ do(248, r("A",213), r("\x23",35), t)}
func Test248x214(t *testing.T){ do(248, r("A",214), r("\x22",34), t)}
func Test248x215(t *testing.T){ do(248, r("A",215), r("\x21",33), t)}
func Test248x216(t *testing.T){ do(248, r("A",216), r("\x20",32), t)}
func Test248x217(t *testing.T){ do(248, r("A",217), r("\x1f",31), t)}
func Test248x218(t *testing.T){ do(248, r("A",218), r("\x1e",30), t)}
func Test248x219(t *testing.T){ do(248, r("A",219), r("\x1d",29), t)}
func Test248x220(t *testing.T){ do(248, r("A",220), r("\x1c",28), t)}
func Test248x221(t *testing.T){ do(248, r("A",221), r("\x1b",27), t)}
func Test248x222(t *testing.T){ do(248, r("A",222), r("\x1a",26), t)}
func Test248x223(t *testing.T){ do(248, r("A",223), r("\x19",25), t)}
func Test248x224(t *testing.T){ do(248, r("A",224), r("\x18",24), t)}
func Test248x225(t *testing.T){ do(248, r("A",225), r("\x17",23), t)}
func Test248x226(t *testing.T){ do(248, r("A",226), r("\x16",22), t)}
func Test248x227(t *testing.T){ do(248, r("A",227), r("\x15",21), t)}
func Test248x228(t *testing.T){ do(248, r("A",228), r("\x14",20), t)}
func Test248x229(t *testing.T){ do(248, r("A",229), r("\x13",19), t)}
func Test248x230(t *testing.T){ do(248, r("A",230), r("\x12",18), t)}
func Test248x231(t *testing.T){ do(248, r("A",231), r("\x11",17), t)}
func Test248x232(t *testing.T){ do(248, r("A",232), r("\x10",16), t)}
func Test248x233(t *testing.T){ do(248, r("A",233), r("\x0f",15), t)}
func Test248x234(t *testing.T){ do(248, r("A",234), r("\x0e",14), t)}
func Test248x235(t *testing.T){ do(248, r("A",235), r("\x0d",13), t)}
func Test248x236(t *testing.T){ do(248, r("A",236), r("\x0c",12), t)}
func Test248x237(t *testing.T){ do(248, r("A",237), r("\x0b",11), t)}
func Test248x238(t *testing.T){ do(248, r("A",238), r("\x0a",10), t)}
func Test248x239(t *testing.T){ do(248, r("A",239), r("\x09", 9), t)}
func Test248x240(t *testing.T){ do(248, r("A",240), r("\x08", 8), t)}
func Test248x241(t *testing.T){ do(248, r("A",241), r("\x07", 7), t)}
func Test248x242(t *testing.T){ do(248, r("A",242), r("\x06", 6), t)}
func Test248x243(t *testing.T){ do(248, r("A",243), r("\x05", 5), t)}
func Test248x244(t *testing.T){ do(248, r("A",244), r("\x04", 4), t)}
func Test248x245(t *testing.T){ do(248, r("A",245), r("\x03", 3), t)}
func Test248x246(t *testing.T){ do(248, r("A",246), r("\x02", 2), t)}
func Test248x247(t *testing.T){ do(248, r("A",247), r("\x01", 1), t)}
func Test248x248(t *testing.T){ do(248, r("A",248), r("\x00",248), t)}
func Test248x249(t *testing.T){ do(248, r("A",249), r("\xf7",247), t)}
func Test248x250(t *testing.T){ do(248, r("A",250), r("\xf6",246), t)}
func Test248x251(t *testing.T){ do(248, r("A",251), r("\xf5",245), t)}
func Test248x252(t *testing.T){ do(248, r("A",252), r("\xf4",244), t)}
func Test248x253(t *testing.T){ do(248, r("A",253), r("\xf3",243), t)}
func Test248x254(t *testing.T){ do(248, r("A",254), r("\xf2",242), t)}
func Test248x255(t *testing.T){ do(248, r("A",255), r("\xf1",241), t)}
func Test256x000(t *testing.T){ do(256, r("A", 0), r("\x00",256), t)}
func Test256x001(t *testing.T){ do(256, r("A", 1), r("\xff",255), t)}
func Test256x002(t *testing.T){ do(256, r("A", 2), r("\xfe",254), t)}
func Test256x003(t *testing.T){ do(256, r("A", 3), r("\xfd",253), t)}
func Test256x004(t *testing.T){ do(256, r("A", 4), r("\xfc",252), t)}
func Test256x005(t *testing.T){ do(256, r("A", 5), r("\xfb",251), t)}
func Test256x006(t *testing.T){ do(256, r("A", 6), r("\xfa",250), t)}
func Test256x007(t *testing.T){ do(256, r("A", 7), r("\xf9",249), t)}
func Test256x008(t *testing.T){ do(256, r("A", 8), r("\xf8",248), t)}
func Test256x009(t *testing.T){ do(256, r("A", 9), r("\xf7",247), t)}
func Test256x010(t *testing.T){ do(256, r("A",10), r("\xf6",246), t)}
func Test256x011(t *testing.T){ do(256, r("A",11), r("\xf5",245), t)}
func Test256x012(t *testing.T){ do(256, r("A",12), r("\xf4",244), t)}
func Test256x013(t *testing.T){ do(256, r("A",13), r("\xf3",243), t)}
func Test256x014(t *testing.T){ do(256, r("A",14), r("\xf2",242), t)}
func Test256x015(t *testing.T){ do(256, r("A",15), r("\xf1",241), t)}
func Test256x016(t *testing.T){ do(256, r("A",16), r("\xf0",240), t)}
func Test256x017(t *testing.T){ do(256, r("A",17), r("\xef",239), t)}
func Test256x018(t *testing.T){ do(256, r("A",18), r("\xee",238), t)}
func Test256x019(t *testing.T){ do(256, r("A",19), r("\xed",237), t)}
func Test256x020(t *testing.T){ do(256, r("A",20), r("\xec",236), t)}
func Test256x021(t *testing.T){ do(256, r("A",21), r("\xeb",235), t)}
func Test256x022(t *testing.T){ do(256, r("A",22), r("\xea",234), t)}
func Test256x023(t *testing.T){ do(256, r("A",23), r("\xe9",233), t)}
func Test256x024(t *testing.T){ do(256, r("A",24), r("\xe8",232), t)}
func Test256x025(t *testing.T){ do(256, r("A",25), r("\xe7",231), t)}
func Test256x026(t *testing.T){ do(256, r("A",26), r("\xe6",230), t)}
func Test256x027(t *testing.T){ do(256, r("A",27), r("\xe5",229), t)}
func Test256x028(t *testing.T){ do(256, r("A",28), r("\xe4",228), t)}
func Test256x029(t *testing.T){ do(256, r("A",29), r("\xe3",227), t)}
func Test256x030(t *testing.T){ do(256, r("A",30), r("\xe2",226), t)}
func Test256x031(t *testing.T){ do(256, r("A",31), r("\xe1",225), t)}
func Test256x032(t *testing.T){ do(256, r("A",32), r("\xe0",224), t)}
func Test256x033(t *testing.T){ do(256, r("A",33), r("\xdf",223), t)}
func Test256x034(t *testing.T){ do(256, r("A",34), r("\xde",222), t)}
func Test256x035(t *testing.T){ do(256, r("A",35), r("\xdd",221), t)}
func Test256x036(t *testing.T){ do(256, r("A",36), r("\xdc",220), t)}
func Test256x037(t *testing.T){ do(256, r("A",37), r("\xdb",219), t)}
func Test256x038(t *testing.T){ do(256, r("A",38), r("\xda",218), t)}
func Test256x039(t *testing.T){ do(256, r("A",39), r("\xd9",217), t)}
func Test256x040(t *testing.T){ do(256, r("A",40), r("\xd8",216), t)}
func Test256x041(t *testing.T){ do(256, r("A",41), r("\xd7",215), t)}
func Test256x042(t *testing.T){ do(256, r("A",42), r("\xd6",214), t)}
func Test256x043(t *testing.T){ do(256, r("A",43), r("\xd5",213), t)}
func Test256x044(t *testing.T){ do(256, r("A",44), r("\xd4",212), t)}
func Test256x045(t *testing.T){ do(256, r("A",45), r("\xd3",211), t)}
func Test256x046(t *testing.T){ do(256, r("A",46), r("\xd2",210), t)}
func Test256x047(t *testing.T){ do(256, r("A",47), r("\xd1",209), t)}
func Test256x048(t *testing.T){ do(256, r("A",48), r("\xd0",208), t)}
func Test256x049(t *testing.T){ do(256, r("A",49), r("\xcf",207), t)}
func Test256x050(t *testing.T){ do(256, r("A",50), r("\xce",206), t)}
func Test256x051(t *testing.T){ do(256, r("A",51), r("\xcd",205), t)}
func Test256x052(t *testing.T){ do(256, r("A",52), r("\xcc",204), t)}
func Test256x053(t *testing.T){ do(256, r("A",53), r("\xcb",203), t)}
func Test256x054(t *testing.T){ do(256, r("A",54), r("\xca",202), t)}
func Test256x055(t *testing.T){ do(256, r("A",55), r("\xc9",201), t)}
func Test256x056(t *testing.T){ do(256, r("A",56), r("\xc8",200), t)}
func Test256x057(t *testing.T){ do(256, r("A",57), r("\xc7",199), t)}
func Test256x058(t *testing.T){ do(256, r("A",58), r("\xc6",198), t)}
func Test256x059(t *testing.T){ do(256, r("A",59), r("\xc5",197), t)}
func Test256x060(t *testing.T){ do(256, r("A",60), r("\xc4",196), t)}
func Test256x061(t *testing.T){ do(256, r("A",61), r("\xc3",195), t)}
func Test256x062(t *testing.T){ do(256, r("A",62), r("\xc2",194), t)}
func Test256x063(t *testing.T){ do(256, r("A",63), r("\xc1",193), t)}
func Test256x064(t *testing.T){ do(256, r("A",64), r("\xc0",192), t)}
func Test256x065(t *testing.T){ do(256, r("A",65), r("\xbf",191), t)}
func Test256x066(t *testing.T){ do(256, r("A",66), r("\xbe",190), t)}
func Test256x067(t *testing.T){ do(256, r("A",67), r("\xbd",189), t)}
func Test256x068(t *testing.T){ do(256, r("A",68), r("\xbc",188), t)}
func Test256x069(t *testing.T){ do(256, r("A",69), r("\xbb",187), t)}
func Test256x070(t *testing.T){ do(256, r("A",70), r("\xba",186), t)}
func Test256x071(t *testing.T){ do(256, r("A",71), r("\xb9",185), t)}
func Test256x072(t *testing.T){ do(256, r("A",72), r("\xb8",184), t)}
func Test256x073(t *testing.T){ do(256, r("A",73), r("\xb7",183), t)}
func Test256x074(t *testing.T){ do(256, r("A",74), r("\xb6",182), t)}
func Test256x075(t *testing.T){ do(256, r("A",75), r("\xb5",181), t)}
func Test256x076(t *testing.T){ do(256, r("A",76), r("\xb4",180), t)}
func Test256x077(t *testing.T){ do(256, r("A",77), r("\xb3",179), t)}
func Test256x078(t *testing.T){ do(256, r("A",78), r("\xb2",178), t)}
func Test256x079(t *testing.T){ do(256, r("A",79), r("\xb1",177), t)}
func Test256x080(t *testing.T){ do(256, r("A",80), r("\xb0",176), t)}
func Test256x081(t *testing.T){ do(256, r("A",81), r("\xaf",175), t)}
func Test256x082(t *testing.T){ do(256, r("A",82), r("\xae",174), t)}
func Test256x083(t *testing.T){ do(256, r("A",83), r("\xad",173), t)}
func Test256x084(t *testing.T){ do(256, r("A",84), r("\xac",172), t)}
func Test256x085(t *testing.T){ do(256, r("A",85), r("\xab",171), t)}
func Test256x086(t *testing.T){ do(256, r("A",86), r("\xaa",170), t)}
func Test256x087(t *testing.T){ do(256, r("A",87), r("\xa9",169), t)}
func Test256x088(t *testing.T){ do(256, r("A",88), r("\xa8",168), t)}
func Test256x089(t *testing.T){ do(256, r("A",89), r("\xa7",167), t)}
func Test256x090(t *testing.T){ do(256, r("A",90), r("\xa6",166), t)}
func Test256x091(t *testing.T){ do(256, r("A",91), r("\xa5",165), t)}
func Test256x092(t *testing.T){ do(256, r("A",92), r("\xa4",164), t)}
func Test256x093(t *testing.T){ do(256, r("A",93), r("\xa3",163), t)}
func Test256x094(t *testing.T){ do(256, r("A",94), r("\xa2",162), t)}
func Test256x095(t *testing.T){ do(256, r("A",95), r("\xa1",161), t)}
func Test256x096(t *testing.T){ do(256, r("A",96), r("\xa0",160), t)}
func Test256x097(t *testing.T){ do(256, r("A",97), r("\x9f",159), t)}
func Test256x098(t *testing.T){ do(256, r("A",98), r("\x9e",158), t)}
func Test256x099(t *testing.T){ do(256, r("A",99), r("\x9d",157), t)}
func Test256x100(t *testing.T){ do(256, r("A",100), r("\x9c",156), t)}
func Test256x101(t *testing.T){ do(256, r("A",101), r("\x9b",155), t)}
func Test256x102(t *testing.T){ do(256, r("A",102), r("\x9a",154), t)}
func Test256x103(t *testing.T){ do(256, r("A",103), r("\x99",153), t)}
func Test256x104(t *testing.T){ do(256, r("A",104), r("\x98",152), t)}
func Test256x105(t *testing.T){ do(256, r("A",105), r("\x97",151), t)}
func Test256x106(t *testing.T){ do(256, r("A",106), r("\x96",150), t)}
func Test256x107(t *testing.T){ do(256, r("A",107), r("\x95",149), t)}
func Test256x108(t *testing.T){ do(256, r("A",108), r("\x94",148), t)}
func Test256x109(t *testing.T){ do(256, r("A",109), r("\x93",147), t)}
func Test256x110(t *testing.T){ do(256, r("A",110), r("\x92",146), t)}
func Test256x111(t *testing.T){ do(256, r("A",111), r("\x91",145), t)}
func Test256x112(t *testing.T){ do(256, r("A",112), r("\x90",144), t)}
func Test256x113(t *testing.T){ do(256, r("A",113), r("\x8f",143), t)}
func Test256x114(t *testing.T){ do(256, r("A",114), r("\x8e",142), t)}
func Test256x115(t *testing.T){ do(256, r("A",115), r("\x8d",141), t)}
func Test256x116(t *testing.T){ do(256, r("A",116), r("\x8c",140), t)}
func Test256x117(t *testing.T){ do(256, r("A",117), r("\x8b",139), t)}
func Test256x118(t *testing.T){ do(256, r("A",118), r("\x8a",138), t)}
func Test256x119(t *testing.T){ do(256, r("A",119), r("\x89",137), t)}
func Test256x120(t *testing.T){ do(256, r("A",120), r("\x88",136), t)}
func Test256x121(t *testing.T){ do(256, r("A",121), r("\x87",135), t)}
func Test256x122(t *testing.T){ do(256, r("A",122), r("\x86",134), t)}
func Test256x123(t *testing.T){ do(256, r("A",123), r("\x85",133), t)}
func Test256x124(t *testing.T){ do(256, r("A",124), r("\x84",132), t)}
func Test256x125(t *testing.T){ do(256, r("A",125), r("\x83",131), t)}
func Test256x126(t *testing.T){ do(256, r("A",126), r("\x82",130), t)}
func Test256x127(t *testing.T){ do(256, r("A",127), r("\x81",129), t)}
func Test256x128(t *testing.T){ do(256, r("A",128), r("\x80",128), t)}
func Test256x129(t *testing.T){ do(256, r("A",129), r("\x7f",127), t)}
func Test256x130(t *testing.T){ do(256, r("A",130), r("\x7e",126), t)}
func Test256x131(t *testing.T){ do(256, r("A",131), r("\x7d",125), t)}
func Test256x132(t *testing.T){ do(256, r("A",132), r("\x7c",124), t)}
func Test256x133(t *testing.T){ do(256, r("A",133), r("\x7b",123), t)}
func Test256x134(t *testing.T){ do(256, r("A",134), r("\x7a",122), t)}
func Test256x135(t *testing.T){ do(256, r("A",135), r("\x79",121), t)}
func Test256x136(t *testing.T){ do(256, r("A",136), r("\x78",120), t)}
func Test256x137(t *testing.T){ do(256, r("A",137), r("\x77",119), t)}
func Test256x138(t *testing.T){ do(256, r("A",138), r("\x76",118), t)}
func Test256x139(t *testing.T){ do(256, r("A",139), r("\x75",117), t)}
func Test256x140(t *testing.T){ do(256, r("A",140), r("\x74",116), t)}
func Test256x141(t *testing.T){ do(256, r("A",141), r("\x73",115), t)}
func Test256x142(t *testing.T){ do(256, r("A",142), r("\x72",114), t)}
func Test256x143(t *testing.T){ do(256, r("A",143), r("\x71",113), t)}
func Test256x144(t *testing.T){ do(256, r("A",144), r("\x70",112), t)}
func Test256x145(t *testing.T){ do(256, r("A",145), r("\x6f",111), t)}
func Test256x146(t *testing.T){ do(256, r("A",146), r("\x6e",110), t)}
func Test256x147(t *testing.T){ do(256, r("A",147), r("\x6d",109), t)}
func Test256x148(t *testing.T){ do(256, r("A",148), r("\x6c",108), t)}
func Test256x149(t *testing.T){ do(256, r("A",149), r("\x6b",107), t)}
func Test256x150(t *testing.T){ do(256, r("A",150), r("\x6a",106), t)}
func Test256x151(t *testing.T){ do(256, r("A",151), r("\x69",105), t)}
func Test256x152(t *testing.T){ do(256, r("A",152), r("\x68",104), t)}
func Test256x153(t *testing.T){ do(256, r("A",153), r("\x67",103), t)}
func Test256x154(t *testing.T){ do(256, r("A",154), r("\x66",102), t)}
func Test256x155(t *testing.T){ do(256, r("A",155), r("\x65",101), t)}
func Test256x156(t *testing.T){ do(256, r("A",156), r("\x64",100), t)}
func Test256x157(t *testing.T){ do(256, r("A",157), r("\x63",99), t)}
func Test256x158(t *testing.T){ do(256, r("A",158), r("\x62",98), t)}
func Test256x159(t *testing.T){ do(256, r("A",159), r("\x61",97), t)}
func Test256x160(t *testing.T){ do(256, r("A",160), r("\x60",96), t)}
func Test256x161(t *testing.T){ do(256, r("A",161), r("\x5f",95), t)}
func Test256x162(t *testing.T){ do(256, r("A",162), r("\x5e",94), t)}
func Test256x163(t *testing.T){ do(256, r("A",163), r("\x5d",93), t)}
func Test256x164(t *testing.T){ do(256, r("A",164), r("\x5c",92), t)}
func Test256x165(t *testing.T){ do(256, r("A",165), r("\x5b",91), t)}
func Test256x166(t *testing.T){ do(256, r("A",166), r("\x5a",90), t)}
func Test256x167(t *testing.T){ do(256, r("A",167), r("\x59",89), t)}
func Test256x168(t *testing.T){ do(256, r("A",168), r("\x58",88), t)}
func Test256x169(t *testing.T){ do(256, r("A",169), r("\x57",87), t)}
func Test256x170(t *testing.T){ do(256, r("A",170), r("\x56",86), t)}
func Test256x171(t *testing.T){ do(256, r("A",171), r("\x55",85), t)}
func Test256x172(t *testing.T){ do(256, r("A",172), r("\x54",84), t)}
func Test256x173(t *testing.T){ do(256, r("A",173), r("\x53",83), t)}
func Test256x174(t *testing.T){ do(256, r("A",174), r("\x52",82), t)}
func Test256x175(t *testing.T){ do(256, r("A",175), r("\x51",81), t)}
func Test256x176(t *testing.T){ do(256, r("A",176), r("\x50",80), t)}
func Test256x177(t *testing.T){ do(256, r("A",177), r("\x4f",79), t)}
func Test256x178(t *testing.T){ do(256, r("A",178), r("\x4e",78), t)}
func Test256x179(t *testing.T){ do(256, r("A",179), r("\x4d",77), t)}
func Test256x180(t *testing.T){ do(256, r("A",180), r("\x4c",76), t)}
func Test256x181(t *testing.T){ do(256, r("A",181), r("\x4b",75), t)}
func Test256x182(t *testing.T){ do(256, r("A",182), r("\x4a",74), t)}
func Test256x183(t *testing.T){ do(256, r("A",183), r("\x49",73), t)}
func Test256x184(t *testing.T){ do(256, r("A",184), r("\x48",72), t)}
func Test256x185(t *testing.T){ do(256, r("A",185), r("\x47",71), t)}
func Test256x186(t *testing.T){ do(256, r("A",186), r("\x46",70), t)}
func Test256x187(t *testing.T){ do(256, r("A",187), r("\x45",69), t)}
func Test256x188(t *testing.T){ do(256, r("A",188), r("\x44",68), t)}
func Test256x189(t *testing.T){ do(256, r("A",189), r("\x43",67), t)}
func Test256x190(t *testing.T){ do(256, r("A",190), r("\x42",66), t)}
func Test256x191(t *testing.T){ do(256, r("A",191), r("\x41",65), t)}
func Test256x192(t *testing.T){ do(256, r("A",192), r("\x40",64), t)}
func Test256x193(t *testing.T){ do(256, r("A",193), r("\x3f",63), t)}
func Test256x194(t *testing.T){ do(256, r("A",194), r("\x3e",62), t)}
func Test256x195(t *testing.T){ do(256, r("A",195), r("\x3d",61), t)}
func Test256x196(t *testing.T){ do(256, r("A",196), r("\x3c",60), t)}
func Test256x197(t *testing.T){ do(256, r("A",197), r("\x3b",59), t)}
func Test256x198(t *testing.T){ do(256, r("A",198), r("\x3a",58), t)}
func Test256x199(t *testing.T){ do(256, r("A",199), r("\x39",57), t)}
func Test256x200(t *testing.T){ do(256, r("A",200), r("\x38",56), t)}
func Test256x201(t *testing.T){ do(256, r("A",201), r("\x37",55), t)}
func Test256x202(t *testing.T){ do(256, r("A",202), r("\x36",54), t)}
func Test256x203(t *testing.T){ do(256, r("A",203), r("\x35",53), t)}
func Test256x204(t *testing.T){ do(256, r("A",204), r("\x34",52), t)}
func Test256x205(t *testing.T){ do(256, r("A",205), r("\x33",51), t)}
func Test256x206(t *testing.T){ do(256, r("A",206), r("\x32",50), t)}
func Test256x207(t *testing.T){ do(256, r("A",207), r("\x31",49), t)}
func Test256x208(t *testing.T){ do(256, r("A",208), r("\x30",48), t)}
func Test256x209(t *testing.T){ do(256, r("A",209), r("\x2f",47), t)}
func Test256x210(t *testing.T){ do(256, r("A",210), r("\x2e",46), t)}
func Test256x211(t *testing.T){ do(256, r("A",211), r("\x2d",45), t)}
func Test256x212(t *testing.T){ do(256, r("A",212), r("\x2c",44), t)}
func Test256x213(t *testing.T){ do(256, r("A",213), r("\x2b",43), t)}
func Test256x214(t *testing.T){ do(256, r("A",214), r("\x2a",42), t)}
func Test256x215(t *testing.T){ do(256, r("A",215), r("\x29",41), t)}
func Test256x216(t *testing.T){ do(256, r("A",216), r("\x28",40), t)}
func Test256x217(t *testing.T){ do(256, r("A",217), r("\x27",39), t)}
func Test256x218(t *testing.T){ do(256, r("A",218), r("\x26",38), t)}
func Test256x219(t *testing.T){ do(256, r("A",219), r("\x25",37), t)}
func Test256x220(t *testing.T){ do(256, r("A",220), r("\x24",36), t)}
func Test256x221(t *testing.T){ do(256, r("A",221), r("\x23",35), t)}
func Test256x222(t *testing.T){ do(256, r("A",222), r("\x22",34), t)}
func Test256x223(t *testing.T){ do(256, r("A",223), r("\x21",33), t)}
func Test256x224(t *testing.T){ do(256, r("A",224), r("\x20",32), t)}
func Test256x225(t *testing.T){ do(256, r("A",225), r("\x1f",31), t)}
func Test256x226(t *testing.T){ do(256, r("A",226), r("\x1e",30), t)}
func Test256x227(t *testing.T){ do(256, r("A",227), r("\x1d",29), t)}
func Test256x228(t *testing.T){ do(256, r("A",228), r("\x1c",28), t)}
func Test256x229(t *testing.T){ do(256, r("A",229), r("\x1b",27), t)}
func Test256x230(t *testing.T){ do(256, r("A",230), r("\x1a",26), t)}
func Test256x231(t *testing.T){ do(256, r("A",231), r("\x19",25), t)}
func Test256x232(t *testing.T){ do(256, r("A",232), r("\x18",24), t)}
func Test256x233(t *testing.T){ do(256, r("A",233), r("\x17",23), t)}
func Test256x234(t *testing.T){ do(256, r("A",234), r("\x16",22), t)}
func Test256x235(t *testing.T){ do(256, r("A",235), r("\x15",21), t)}
func Test256x236(t *testing.T){ do(256, r("A",236), r("\x14",20), t)}
func Test256x237(t *testing.T){ do(256, r("A",237), r("\x13",19), t)}
func Test256x238(t *testing.T){ do(256, r("A",238), r("\x12",18), t)}
func Test256x239(t *testing.T){ do(256, r("A",239), r("\x11",17), t)}
func Test256x240(t *testing.T){ do(256, r("A",240), r("\x10",16), t)}
func Test256x241(t *testing.T){ do(256, r("A",241), r("\x0f",15), t)}
func Test256x242(t *testing.T){ do(256, r("A",242), r("\x0e",14), t)}
func Test256x243(t *testing.T){ do(256, r("A",243), r("\x0d",13), t)}
func Test256x244(t *testing.T){ do(256, r("A",244), r("\x0c",12), t)}
func Test256x245(t *testing.T){ do(256, r("A",245), r("\x0b",11), t)}
func Test256x246(t *testing.T){ do(256, r("A",246), r("\x0a",10), t)}
func Test256x247(t *testing.T){ do(256, r("A",247), r("\x09", 9), t)}
func Test256x248(t *testing.T){ do(256, r("A",248), r("\x08", 8), t)}
func Test256x249(t *testing.T){ do(256, r("A",249), r("\x07", 7), t)}
func Test256x250(t *testing.T){ do(256, r("A",250), r("\x06", 6), t)}
func Test256x251(t *testing.T){ do(256, r("A",251), r("\x05", 5), t)}
func Test256x252(t *testing.T){ do(256, r("A",252), r("\x04", 4), t)}
func Test256x253(t *testing.T){ do(256, r("A",253), r("\x03", 3), t)}
func Test256x254(t *testing.T){ do(256, r("A",254), r("\x02", 2), t)}
func Test256x255(t *testing.T){ do(256, r("A",255), r("\x01", 1), t)}
