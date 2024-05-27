package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)


func GetUserId(Username string, accessToken string) (interface{}, error) {
	url := "https://34.93.102.191:18080/auth/admin/realms/camunda-platform/users"
	method := "GET"
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println("Error:", err)
	}
	req.Header.Add("Authorization", accessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := Client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}

	var userIdExtractor []map[string]interface{}

	checkUserName := strings.ToLower(Username)
	err = json.NewDecoder(resp.Body).Decode(&userIdExtractor)
	if err != nil {
		fmt.Println("Error", err)
	}
	for _, value := range userIdExtractor {
		if value["username"] == checkUserName {
			IdUser := value["id"]
			return IdUser, nil
		}
	}
	return nil, err
}