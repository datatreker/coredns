package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// MimeType is the DoH mimetype that should be used.
const MimeType = "application/dns-message"
const JsonType = "text/html"

// Path is the URL path that should be used.
const DoHPath = "/dns-query"
const JsonPath = "/resolve"

func Support(urlPath string) bool {
	if urlPath == DoHPath || urlPath == JsonPath {
		return true
	}
	return false
}

// NewRequest returns a new DoH request given a method, URL (without any paths, so exclude /dns-query) and dns.Msg.
func NewRequest(method, url string, m *dns.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	switch method {
	case http.MethodGet:
		b64 := base64.RawURLEncoding.EncodeToString(buf)

		req, err := http.NewRequest(http.MethodGet, "https://"+url+DoHPath+"?dns="+b64, nil)
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	case http.MethodPost:
		req, err := http.NewRequest(http.MethodPost, "https://"+url+DoHPath+"?bla=foo:443", bytes.NewReader(buf))
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	default:
		return nil, fmt.Errorf("method not allowed: %s", method)
	}

}

// ResponseToMsg converts a http.Response to a dns message.
func ResponseToMsg(resp *http.Response) (*dns.Msg, error) {
	defer resp.Body.Close()

	return toMsg(resp.Body)
}

// RequestToMsg converts a http.Request to a dns message.
func RequestToMsg(req *http.Request) (*dns.Msg, error) {
	switch req.Method {
	case http.MethodGet:
		return requestToMsgGet(req)

	case http.MethodPost:
		return requestToMsgPost(req)

	default:
		return nil, fmt.Errorf("method not allowed: %s", req.Method)
	}

}

// requestToMsgPost extracts the dns message from the request body.
func requestToMsgPost(req *http.Request) (*dns.Msg, error) {
	defer req.Body.Close()
	return toMsg(req.Body)
}

// requestToMsgGet extract the dns message from the GET request.
func requestToMsgGet(req *http.Request) (*dns.Msg, error) {
	if IsJsonRequest(req) {
		values := req.URL.Query()
		name, ok := values["name"]
		if !ok {
			return nil, fmt.Errorf("no 'name' query parameter found")
		}

		if !validateDomainName(name[0]) {
			return nil, fmt.Errorf("'name' is an invalid domain name")
		}

		types, ok := values["type"]
		var rType string
		if !ok {
			rType = "A"
		} else {
			rType = strings.ToUpper(types[0])
		}
		var qType uint16
		if result, err := strconv.Atoi(rType); err == nil {
			qType = uint16(result)
			if _, ok = dns.TypeToString[qType]; !ok {
				return nil, fmt.Errorf("invalid type %q", rType)
			}
		} else {
			if qType, ok = dns.StringToType[strings.ToUpper(rType)]; !ok {
				return nil, fmt.Errorf("invalid type %q", rType)
			}
		}

		cds, ok := values["cd"]
		var cd bool
		if !ok {
			cd = false
		} else {
			switch cds[0] {
			case "true":
				cd = true
			case "false":
				cd = false
			}
		}

		dos, ok := values["do"]
		var o *dns.OPT
		if ok && dos[0] == "true" {
			o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			o.SetDo()

		}

		ecs, ok := values["edns_client_subnet"]
		var e *dns.EDNS0_SUBNET
		if ok {
			if o == nil {
				o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			}
			e = new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			address := strings.Split(ecs[0], "/")[0]
			netmask := strings.Split(ecs[0], "/")[1]
			//fmt.Printf("address:%s\n", address)
			//fmt.Printf("netmask:%s\n", netmask)
			if strings.Contains(ecs[0], ".") {
				e.Family = 1
				e.Address = net.ParseIP(address).To4()
			} else {
				e.Family = 2
				e.Address = net.ParseIP(address)
			}
			//fmt.Printf("e.address:%s\n", e.Address)
			if result, err := strconv.Atoi(netmask); err != nil {
				e.SourceNetmask = uint8(result)
			}
			e.SourceScope = 0
			//fmt.Printf("opt:%s\n", e)
			o.Option = append(o.Option, e)
			//fmt.Printf("opt:%s\n", e)
		}

		m := new(dns.Msg)
		m.Opcode = dns.OpcodeQuery
		m.CheckingDisabled = cd
		m.Question = append(m.Question, dns.Question{Name: name[0] + ".", Qtype: qType, Qclass: dns.ClassINET})
		//fmt.Printf("o:%s\n", o)
		if o != nil {
			m.Extra = append(m.Extra, o)
		}
		//fmt.Printf("msg:%s\n", m)

		msg, err := m.Pack()
		if err != nil {
		}
		return base64ToMsg(base64.RawURLEncoding.EncodeToString(msg))
	} else {
		//fmt.Printf("DoH request:%s\n", req.URL)
		values := req.URL.Query()
		b64, ok := values["dns"]
		if !ok {
			return nil, fmt.Errorf("no 'dns' query parameter found")
		}
		if len(b64) != 1 {
			return nil, fmt.Errorf("multiple 'dns' query values found")
		}
		return base64ToMsg(b64[0])
	}

}

func OPTtoString(opt *dns.OPT) (string, error) {
	options := make(map[string]string)
	options["version"] = strconv.Itoa(int(opt.Version()))
	if opt.Do() {
		options["flags"] = "do"
	}
	options["udp"] = strconv.Itoa(int(opt.UDPSize()))
	for _, o := range opt.Option {
		switch o.(type) {
		case *dns.EDNS0_NSID:
			/*
				s := o.String()
				h, e := o.(*dns.EDNS0_NSID).pack()
				var r string
				if e == nil {
					for _, c := range h {
						r += "(" + string(c) + ")"
					}
					s += "  " + r
				}
			*/
			options["NSID"] = o.String()
		case *dns.EDNS0_SUBNET:
			options["SUBNET"] = o.String()
		case *dns.EDNS0_COOKIE:
			options["COOKIE"] = o.String()
		case *dns.EDNS0_UL:
			options["UPDATE LEASE"] = o.String()
		case *dns.EDNS0_LLQ:
			options["LONG LIVED QUERIES"] = o.String()
		case *dns.EDNS0_DAU:
			options["DNSSEC ALGORITHM UNDERSTOOD"] = o.String()
		case *dns.EDNS0_DHU:
			options["DS HASH UNDERSTOOD"] = o.String()
		case *dns.EDNS0_N3U:
			options["NSEC3 HASH UNDERSTOOD"] = o.String()
		case *dns.EDNS0_LOCAL:
			options["LOCAL OPT"] = o.String()
		case *dns.EDNS0_PADDING:
			options["PADDING"] = o.String()
		}
	}
	j, err := json.Marshal(options)
	return string(j), err
}

func toMsg(r io.ReadCloser) (*dns.Msg, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	err = m.Unpack(buf)
	return m, err
}

func base64ToMsg(b64 string) (*dns.Msg, error) {
	buf, err := b64Enc.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	err = m.Unpack(buf)

	return m, err
}

var b64Enc = base64.RawURLEncoding

type Question struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type RR struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type Response struct {
	Status     string     `json:"Status"`
	TC         bool       `json:"TC"`
	RD         bool       `json:"RD"`
	RA         bool       `json:"RA"`
	AD         bool       `json:"AD"`
	CD         bool       `json:"CD"`
	Question   []Question `json:"Question"`
	Answer     []RR       `json:"Answer"`
	Authority  []RR       `json:"Authority"`
	Additional []RR       `json:"Additional"`
}

func IsJsonRequest(req *http.Request) bool {
	if req.URL.Path == JsonPath {
		return true
	}
	return false
}

func validateDomainName(domain string) bool {
	RegExp := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+.?`)
	return RegExp.MatchString(domain)
}
