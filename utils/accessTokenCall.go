package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func AccessTokenCall() (accessToken interface{}, err error) {

	url := "https://34.93.102.191:18080/auth/realms/camunda-platform/protocol/openid-connect/token"
	method := "POST"

	payload := strings.NewReader("client_id=access_token&client_secret=ZBKi3qEBDKHhszZfwwiFdsvq0pMS3OvH&grant_type=password&username=demo&password=demo")

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Error:%v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := Client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Error:%v", err)
	}
	defer res.Body.Close()

	var Token_ResponseData map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&Token_ResponseData)
	if err != nil {
		fmt.Println("Error", err)
	}

	return Token_ResponseData["access_token"].(string), nil

}
