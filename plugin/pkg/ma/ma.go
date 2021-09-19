package ma

import (
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	rootUrlPath      = "/ma-api/"
	apiServerAddress = "http://127.0.0.1:9527"
	defaultTimeout   = time.Duration(10)
	defaultTTL       = 300
	defaultMimeType  = "application/json"
)

type ResolveResult struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

type IDCodeResolver struct {
	cache *badger.DB
}

func NewIDCodeResolver() (*IDCodeResolver, error) {
	db, err := badger.Open(badger.DefaultOptions("/tmp/badger").WithBypassLockGuard(true))
	if err != nil {
		return nil, err
	}
	return &IDCodeResolver{cache: db}, nil
}

func (srv *IDCodeResolver) Close() {
	srv.cache.Close()
}

func Support(urlPath string) bool {
	if strings.HasPrefix(urlPath, rootUrlPath) {
		return true
	}
	return false
}

func createHTTPClient() *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   defaultTimeout * time.Second,
			KeepAlive: defaultTimeout * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: defaultTimeout * time.Second,

		ExpectContinueTimeout: defaultTimeout * time.Second,
		ResponseHeaderTimeout: defaultTimeout * time.Second,
		MaxIdleConns:          10,
		MaxConnsPerHost:       0,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   defaultTimeout * time.Second,
	}
	return client
}
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (srv *IDCodeResolver) Handle(w http.ResponseWriter, r *http.Request) {
	client := createHTTPClient()
	request, err := http.NewRequest("GET", apiServerAddress+r.URL.RequestURI(), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	copyHeader(request.Header, r.Header)
	resp, err := client.Do(request)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		w.WriteHeader(http.StatusExpectationFailed)
		w.Write([]byte(err.Error()))
		return
	}
	var resolveResult ResolveResult
	json.Unmarshal(body, &resolveResult)
	result, err := json.Marshal(resolveResult.Data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	if resp.StatusCode == http.StatusOK {
		w.Header().Set("Content-Type", defaultMimeType)
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", defaultTTL))
		w.Header().Set("Content-Length", strconv.Itoa(len(result)))
		w.WriteHeader(http.StatusOK)
		w.Write(result)
	} else {
		w.Header().Set("Content-Type", defaultMimeType)
		w.Header().Set("Content-Length", strconv.Itoa(len(result)))
		w.WriteHeader(resp.StatusCode)
		w.Write(result)
	}

}

func (srv *IDCodeResolver) updateCache(key string, data []byte) error {
	err := srv.cache.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), data).WithTTL(time.Hour)
		err := txn.SetEntry(e)
		return err
	})
	return err
}

func (srv *IDCodeResolver) getFromCache(key string) ([]byte, error) {
	var data []byte
	err := srv.cache.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			data = append([]byte{}, val...)
			return nil
		})
		return err
	})
	return data, err
}
