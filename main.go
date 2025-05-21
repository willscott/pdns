package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/bwesterb/go-zonefile"
)

var origin = flag.String("origin", "", "Origin for the zone to update")
var fZone = flag.String("fzone", "", "Forward zone to use for the server")
var rZone = flag.String("rzone", "", "Reverse zone to use for the server")
var bind = flag.String("bind", ":8080", "Bind address for the server")
var secret = flag.String("secret", "", "Secret to allow updates")

var updateMutex = &sync.Mutex{}

func main() {
	flag.Parse()

	s := http.Server{
		Addr: *bind,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")

			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			query := r.URL.Query()
			if query.Get("secret") != *secret {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden"))
				return
			}

			name := query.Get("name")
			ip := query.Get("ip")
			if name == "" || ip == "" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Missing name or ip"))
				return
			}
			if err := Set(name, ip); err != nil {
				log.Printf("Error setting record: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Error: %v", err)
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}),
	}
	s.ListenAndServe()
}

func Set(name string, ip string) error {
	updateMutex.Lock()
	defer updateMutex.Unlock()

	nip, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}
	rname := fmt.Sprintf("%s.%s.", name, *origin)
	if nip.Is6() {
		if err = UpdateRecordInFile(*fZone, name, "AAAA", ip); err != nil {
			return fmt.Errorf("could not update forward AAAA record: %v", err)
		}
		ipb := nip.As16()
		ipHex := fmt.Sprintf("%x", ipb)
		rHex := ""
		for i := len(ipHex); i > 0; i -= 1 {
			rHex += fmt.Sprintf("%s.", ipHex[i-1:i])
		}
		xformIP := fmt.Sprintf("%sip6.arpa.", rHex)
		if err = UpdateRecordInFile(*rZone, xformIP, "PTR", rname); err != nil {
			return fmt.Errorf("could not update reverse A PTR record: %v", err)
		}
	} else {
		if err = UpdateRecordInFile(*fZone, name, "A", ip); err != nil {
			return fmt.Errorf("could not update forward A record: %v", err)
		}
		ipb := nip.As4()
		xformIP := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ipb[3], ipb[2], ipb[1], ipb[0])
		if err = UpdateRecordInFile(*rZone, xformIP, "PTR", rname); err != nil {
			return fmt.Errorf("could not update reverse A PTR record: %v", err)
		}
	}

	// try now to reload
	cmd := exec.Command("/usr/bin/systemctl", "reload", "nsd")
	err = cmd.Run()

	return err
}

func UpdateRecordInFile(fName string, name, rtype, value string) error {
	file, err := os.OpenFile(fName, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	currentData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	zf, perr := zonefile.Load(currentData)
	if perr != nil {
		return perr
	}

	soaOK := false
	rcrdFnd := false
	for _, e := range zf.Entries() {
		if bytes.Equal(e.Type(), []byte(rtype)) && bytes.Equal(e.Domain(), []byte(name)) {
			rcrdFnd = true
			if err := e.SetValue(0, []byte(value)); err != nil {
				log.Print("Could not set value:", err)
				return err
			}
		}
		if !bytes.Equal(e.Type(), []byte("SOA")) {
			continue
		}
		vs := e.Values()
		if len(vs) != 7 {
			return fmt.Errorf("wrong number of parameters to SOA line")
		}
		serial, err := strconv.Atoi(string(vs[2]))
		if err != nil {
			log.Print("Could not parse serial:", err)
			return err
		}
		e.SetValue(2, []byte(strconv.Itoa(serial+1)))
		soaOK = true
	}
	if !soaOK {
		return fmt.Errorf("could not find SOA entry")
	}
	if !rcrdFnd {
		// add
		if rtype == "PTR" {
			rr, err := zonefile.ParseEntry([]byte(fmt.Sprintf("%s IN %s %s", name, rtype, value)))
			if err != nil {
				return err
			}
			zf.AddEntry(rr)
		} else {
			rr, err := zonefile.ParseEntry([]byte(fmt.Sprintf("%s %s %s", name, rtype, value)))
			if err != nil {
				return err
			}
			zf.AddEntry(rr)
		}
	}

	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	if _, err := file.Write(zf.Save()); err != nil {
		return err
	}
	if !rcrdFnd {
		file.WriteString("\n")
	}
	return nil
}
