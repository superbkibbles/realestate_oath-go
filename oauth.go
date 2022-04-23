package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/superbkibbles/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic    = "X-Public"
	heaederXCallerID = "X-Caller-Id"
	paramAccessToken = "access_token"
	test             = "test"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthClient struct {
}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(heaederXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(heaederXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func AuthentuicateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(heaederXCallerID, strconv.FormatInt(at.UserID, 10))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerErr("invalid restClient response when trying to get access token", nil)
	}
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerErr("Invalid error interface when trying to get access token", nil)
		}
		return nil, restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerErr("error while trying to unmarshal access token response", nil)
	}
	return &at, nil
}
