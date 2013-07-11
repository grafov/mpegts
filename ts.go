
package main

import (
	"os"
	"fmt"
	_ "io"
	"io/ioutil"
	"log"
)

type tsFilter struct {
	pos, size int
	codec int
	header, data []byte
}

func rb16(r []byte) int {
	return int(r[0])<<8 + int(r[1])
}

func ri16(r []byte) int {
	return int(int16(uint16(r[0])<<8 + uint16(r[1])))
}

func ri8(r []byte) int {
	return int(int8(r[0]))
}

func rb8(r []byte) int {
	return int(r[0])
}

func parsePesPts(r []byte) int64 {
	return (int64(r[0])&0x0e)<<29 |
			int64(rb16(r[1:])>>1)<<15 |
			int64(rb16(r[3:]))>>1
}

type tsStream struct {
	tsmap map[int]*tsFilter
	f *os.File
}

func Open(filename string) (m *tsStream, err error) {
	m = &tsStream{}
	m.tsmap = map[int]*tsFilter{}
	m.f, err = os.Open(filename)
	return
}

func (m *tsStream) Close() {
	m.f.Close()
}

const (
	H264 = 1
	AAC = 2
)

type tsPacket struct {
	codec int
	data []byte
}

func (m *tsStream) ReadDur(dur float32) (pkts []tsPacket, err error) {
	buf := make([]byte, 188)
	for i := 0; i < 3000; i++ {
		_, err = m.f.Read(buf)
		if err != nil {
			break
		}

		pid := rb16(buf[1:3])&0x1fff
		log.Printf("#%d pid 0x%x counter %d", i, pid, int(buf[3]&0x0f))

		tss := m.tsmap[pid]
		if tss == nil {
			tss = &tsFilter{}
			m.tsmap[pid] = tss
			log.Printf(" new tss")
		}

		isStart := (buf[1]&0x40) != 0
		hasPay := (buf[3] & 0x10) != 0
		hasAdapt := (buf[3] & 0x20) != 0
		log.Printf(" %v %v %v", isStart, hasPay, hasAdapt)

		if !hasPay {
			continue
		}

		var p []byte

		p = buf[4:]
		if hasAdapt {
			pos := 1+int(p[0])
			if pos > len(p) {
				continue
			}
			p = p[pos:]
		}

		parsePAT := func () {
			p := tss.data
			if len(p) < 8 {
				return
			}
			tid := rb8(p)
			p = p[8:]
			if tid != 0x0 {
				return
			}
			for len(p) >= 4 {
				sid := ri16(p)
				pmtpid := rb16(p[2:])&0x1fff
				if sid < 0 {
					break
				}
				log.Printf("  pat: sid 0x%x pid 0x%x", sid, pmtpid)
				p = p[4:]
			}
		}

		parsePMT := func () {
			p := tss.data
			if len(p) < 8 {
				return
			}
			tid := rb8(p)
			p = p[8:]
			log.Printf("  pmt: tid 0x%x", tid)
			if tid != 0x2 {
				return
			}
			if len(p) < 4 {
				return
			}
			pcrpid := rb16(p)
			proglen := rb16(p[2:])
			p = p[4:]
			log.Printf("  pmt: pcr 0x%x len %d", pcrpid, proglen)
			for len(p) >= 5 {
				strtype := rb8(p)
				strpid := rb16(p[1:])&0x1fff
				desclen := rb16(p[3:])&0xfff
				log.Printf("  pmt: strtype 0x%x strpid 0x%x desclen %d", strtype, strpid, desclen)
				t := m.tsmap[strpid]
				if t == nil {
					t = &tsFilter{}
					switch strtype {
					case 0x0f:
						t.codec = AAC
					case 0x1b:
						t.codec = H264
					}
					m.tsmap[strpid] = t
				}
				if 5+desclen > len(p) {
					break
				}
				p = p[5+desclen:]
			}
		}

		parseSec2 := func (p []byte) {
			tss.data = append(tss.data, p...)
			if tss.size <= 0 {
				if len(tss.data) >= 3 {
					tss.size = rb16(tss.data[1:3])&0xfff + 3
					if tss.size > 4096 {
						tss.size = -1
						return
					}
				}
			}
			if len(tss.data) >= tss.size {
				log.Printf("  secdata %d bytes", tss.size)
				tss.data = tss.data[0:tss.size]
				if pid == 0x00 {
					parsePAT()
				}
				if pid == 0x100 {
					parsePMT()
				}
				tss.data = []byte{}
				tss.size = 0
			}
		}

		parseSec := func () {
			if isStart {
				if len(p) < 1 {
					return
				}
				sz := rb8(p)
				p = p[1:]
				if sz > len(p) {
					return
				}
				parseSec2(p)
			} else {
				parseSec2(p)
			}
		}

		parsePes2 := func () {
			log.Printf("  pesdata %d bytes", tss.pos)
			tss.data = tss.data[:tss.pos]
			pkts = append(pkts, tsPacket{codec:tss.codec, data:tss.data})
		}

		parsePes := func () {
			if isStart {
				if len(tss.data) > 0 {
					parsePes2()
				}
				tss.header = make([]byte, 9)
				copy(tss.header, p[0:9])
				code := int(tss.header[3]) | 0x100
				totsiz := rb16(tss.header[4:])
				hdrsiz := int(tss.header[8])
				flags := int(tss.header[7])

				log.Printf(" header %v code 0x%x totsize %v hdrsiz %d flags 0x%x",
				tss.header, code, totsiz, hdrsiz, flags)

				if hdrsiz > 0 {
					hdr2 := p[9:9+hdrsiz]
					log.Printf("  hdr2 %v", hdr2)
					dts := parsePesPts(hdr2)
					log.Printf("  dts %v", dts)
				}
				if totsiz == 0 {
					totsiz = 200*1024
				}

				tss.data = make([]byte, totsiz)
				tss.pos = 0
				p = p[9+hdrsiz:]
			}

			if len(tss.data) > 0 {
				l := tss.pos+len(p)
				if l > len(tss.data) {
					l = len(tss.data)
				}
				copy(tss.data[tss.pos:l], p)
				tss.pos += len(p)
			}

			if tss.pos >= len(tss.data) {
				parsePes2()
			}
		}

		if pid == 0x00 || pid == 0x100 {
			parseSec()
		} else {
			parsePes()
		}
	}
	return
}

func main() {
	log.SetOutput(os.Stdout)
	s, _ := Open("/work/0/a.ts")
	pkts, _ := s.ReadDur(1)
	i := 0
	os.Mkdir("/tmp/264", 0777)
	for _, p := range pkts {
		if p.codec == H264 {
			filename := fmt.Sprintf("/tmp/264/%d.264", i)
			ioutil.WriteFile(filename, p.data, 0777)
			log.Printf("#%d %d bytes", i, len(p.data))
			i++
		}
	}
	s.Close()
}

