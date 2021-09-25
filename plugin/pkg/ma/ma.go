package ma

import (
	"encoding/json"
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	nodeUrlPath      = "/ma/node"
	dataUrlPath      = "/ma/data"
	apiServerAddress = "http://124.126.76.128:31026/ma-api/analysis"
	defaultTimeout   = time.Duration(10)
	defaultTTL       = 300
	defaultMimeType  = "application/json"
)

type ResolveResult struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Success bool   `json:"success"`
	Data    string `json:"data"`
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
	if urlPath == nodeUrlPath || urlPath == dataUrlPath {
		return true
	}
	return false
}

func isQueryNode(urlPath string) bool {
	if urlPath == nodeUrlPath {
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
	url := apiServerAddress + "/ma"
	queryType := "data"
	if isQueryNode(r.URL.Path) {
		url = apiServerAddress + "/nodeInfo"
		queryType = "node"
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := queryType + ":" + id
	result, _ := srv.getFromCache(key)
	if result != nil {
		w.Header().Set("Content-Type", defaultMimeType)
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", defaultTTL))
		w.Header().Set("Content-Length", strconv.Itoa(len(result)))
		w.WriteHeader(http.StatusOK)
		w.Write(result)
		return
	}
	url = fmt.Sprintf("%s?analysisUrl=%s", url, id)
	println(fmt.Sprintf("url:%s, type:%s", url, queryType))
	request, err := http.NewRequest("GET", url, nil)
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
	println(string(body))
	var resolveResult ResolveResult
	err = json.Unmarshal(body, &resolveResult)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	println(fmt.Sprintf("code:%s, message:%s, success:%v, data:%v", resolveResult.Code, resolveResult.Message, resolveResult.Success, resolveResult.Data))
	if resp.StatusCode == http.StatusOK {
		statusCode := srv.resolveReturnCode(resolveResult.Code)
		if statusCode == http.StatusOK {
			srv.updateCache(key, []byte(resolveResult.Data))
			w.Header().Set("Content-Type", defaultMimeType)
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", defaultTTL))
			w.Header().Set("Content-Length", strconv.Itoa(len(resolveResult.Data)))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(resolveResult.Data))
		} else {
			w.Header().Set("Content-Type", defaultMimeType)
			w.Header().Set("Content-Length", strconv.Itoa(len(resolveResult.Data)))
			w.WriteHeader(statusCode)
			w.Write([]byte(resolveResult.Data))
		}

	} else {
		w.Header().Set("Content-Type", defaultMimeType)
		w.Header().Set("Content-Length", strconv.Itoa(len(resolveResult.Data)))
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(resolveResult.Data))
	}

}

func (srv *IDCodeResolver) updateCache(key string, data []byte) error {
	err := srv.cache.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), data).WithTTL(time.Minute)
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

func (srv *IDCodeResolver) resolveReturnCode(code string) int {
	switch code {
	case "200":
		return http.StatusOK
	case "001001":
		return http.StatusBadRequest
	case "200001":
		return http.StatusBadRequest
	case "200002":
		return http.StatusUnauthorized
	default:
		return http.StatusNotFound
	}
}
