package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/gorilla/schema"
)

var (
	ErrUndefinedErrror = errors.New("Undefined error")
)

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	CallBackURL  string `json:"url"`
}

type HTTPResponse struct {
	Body   []byte
	Code   int
	Header http.Header
	Status string
	Cookie []*http.Cookie
}

func QueryMarshall(in interface{}) url.Values {
	encoder := schema.NewEncoder()
	urlValue := url.Values{}

	if err := encoder.Encode(in, urlValue); err != nil {
		log.Println("marsahll error", err)
	}
	return urlValue
}

func QueryUnmarshall(v interface{}, uv url.Values) error {
	decoder := schema.NewDecoder()
	return decoder.Decode(v, uv)
}

func (r *HTTPResponse) UnMarshall(data interface{}) error {
	if r.Code >= 400 {
		return errors.New(fmt.Sprintf("%v %s", r.Code, string(r.Body)))
	}

	if err := json.Unmarshal(r.Body, data); err != nil {
		return err
	}

	return nil
}

// Creates a new file upload
func NewBufferMultiPart(paramName, path string) (*bytes.Buffer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(part, file)

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return body, err
}

type HTTPReq struct {
	Url    string
	Cookie []*http.Cookie
	Header map[string]string
	Body   interface{}
	Token  string
}

func Get(r HTTPReq) (*HTTPResponse, error) {
	resp, err := http.Get(r.Url)
	// res := new(HTTPResponse)
	if err != nil {
		log.Printf("get error %s", err)
		return nil, err
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("get error %s", err)
			return nil, err
		}

		return &HTTPResponse{body, resp.StatusCode, resp.Header, resp.Status, resp.Cookies()}, nil
	}

	return nil, ErrUndefinedErrror
}

func GetReq(r HTTPReq) (*HTTPResponse, error) {

	params := ""
	if r.Body != nil {
		params = "?"
		//map string body
		if body, ok := r.Body.(map[string]interface{}); ok {
			for k, v := range body {
				params = params + "&" + k + "=" + fmt.Sprintf("%v", v)
			}
		} else {
			// struct body
			params = params + QueryMarshall(r.Body).Encode()
		}
	}

	req, err := http.NewRequest("GET", r.Url+params, nil)
	if err != nil {
		log.Printf("post error %s", err)
		return nil, err
	}

	for k, v := range r.Header {
		req.Header.Set(k, v)
	}

	// req.Header.Set("Content-Type", "application/json")

	if r.Token != "" {
		req.Header.Set("Authorization", r.Token)
	}

	for _, coc := range r.Cookie {
		cookie := http.Cookie{Name: coc.Name, Value: coc.Value}
		req.AddCookie(&cookie)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("get error %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return &HTTPResponse{body, resp.StatusCode, resp.Header, resp.Status, resp.Cookies()}, nil
}

// HttpClient http req wrapper, default post method
func HttpClient(r HTTPReq, method ...string) (*HTTPResponse, error) {
	buf := new(bytes.Buffer)

	switch body := r.Body.(type) {
	case url.Values:
		buf = bytes.NewBufferString(body.Encode())
	case *bytes.Buffer:
		buf = body
	case []byte:
		buf = bytes.NewBuffer(body)
	default:
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		buf = bytes.NewBuffer(data)
	}

	methodClient := "POST"
	if len(method) > 0 {
		methodClient = method[0]
	}

	req, err := http.NewRequest(methodClient, r.Url, buf)
	if err != nil {
		log.Printf("%s error %s", methodClient, err)
		return nil, err
	}

	if r.Header == nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if r.Token != "" {
		req.Header.Set("Authorization", r.Token)
	}

	for k, v := range r.Header {
		req.Header.Set(k, v)
	}

	for _, coc := range r.Cookie {
		req.AddCookie(coc)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s error %s", methodClient, err)
		return nil, err
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return &HTTPResponse{body, resp.StatusCode, resp.Header, resp.Status, resp.Cookies()}, nil
}

func (r *HTTPReq) GET() (*HTTPResponse, error) {
	if r == nil || r.Url == "" {
		return nil, errors.New("value/token/url must not nil")
	}
	return GetReq(*r)
}

func (r *HTTPReq) POST() (*HTTPResponse, error) {
	if r == nil || r.Url == "" {
		return nil, errors.New("value/token/url must not nil")
	}
	return HttpClient(*r)
}

func (r *HTTPReq) PATCH() (*HTTPResponse, error) {
	if r == nil || r.Url == "" {
		return nil, errors.New("value/token/url must not nil")
	}
	return HttpClient(*r, "PATCH")
}

func (r *HTTPReq) PUT() (*HTTPResponse, error) {
	if r == nil || r.Url == "" {
		return nil, errors.New("value/token/url must not nil")
	}
	return HttpClient(*r, "PUT")
}

func (r *HTTPReq) DELETE() (*HTTPResponse, error) {
	if r == nil || r.Url == "" {
		return nil, errors.New("value/token/url must not nil")
	}

	return HttpClient(*r, "DELETE")
}
