package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"tlz_go/utils"

	"github.com/sethvargo/go-password/password"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Id struct {
	Id string `json:"id"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type IncomingData struct {
	Id       string     `json:"id"`
	Variable []Variable `json:"variables"`
}
type User struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
	PhoneNo   string `json:"phoneno"`
	// Username  string `json:"username"`
	// Password  string `json:"password"`
}

type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

var client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func accessTokenCall() (accessToken interface{}, err error) {

	url := "https://34.93.102.191:18080/auth/realms/camunda-platform/protocol/openid-connect/token"
	method := "POST"

	payload := strings.NewReader("client_id=tasklist&client_secret=XALaRPl5qwTEItdwCMiPS62nVpKs7dL7&grant_type=client_credentials")
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Error:%v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Error:%v", err)
	}
	defer res.Body.Close()

	var Token_ResponseData map[string]interface{}
	json.NewDecoder(res.Body).Decode(&Token_ResponseData)

	return Token_ResponseData["access_token"].(string), nil
}

func getTasksHandler(response http.ResponseWriter, request *http.Request) {

	accessToken, err := accessTokenCall()
	// fmt.Println(accessToken)
	if err != nil || accessToken == nil {
		fmt.Println("Error In Getting Token:", err)
	}

	// var idBody Id

	// json.NewDecoder(request.Body).Decode(&idBody)
	// if idBody.Id == "" {
	// 	handleError(response, "Do Provide The ID")
	// 	return
	// }
	// fmt.Println(idBody.Id)

	// myid := idBody.Id

	url := "http://34.93.102.191:8082/v1/tasks/search"
	method := "POST"

	// payload := fmt.Sprintf(`{
	// 	"state": "CREATED",
	// 	"assigned": true,
	// 	"assignee":	"%s"
	// }`, myid)

	bodyIoUtilData, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	reader := strings.NewReader(string(bodyIoUtilData))
	fmt.Println(reader)

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	Token := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", Token)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	// data,err:=ioutil.ReadAll(res.Body)
	// // fmt.Println(err)
	// fmt.Println(string(data))

	// getData := string(data)

	var getTaskData []map[string]interface{}

	err = json.NewDecoder(res.Body).Decode(&getTaskData)

	if err != nil {
		fmt.Println("Error Decoding getTaskData:", err)
	}
	// fmt.Println(getTaskData)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")

	if len(getTaskData) == 0 {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"Success": "True",
			"Message": "No Remaining Tasks",
			"Data":    getTaskData,
		})
		return
	}
	json.NewEncoder(response).Encode(getTaskData)

}

// func login(response http.ResponseWriter, request *http.Request) {

// }

func ValidateLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var req LoginRequest
		err := json.NewDecoder(request.Body).Decode(&req)
		if err != nil {
			fmt.Println("Error While Decoding in Validation:", err)
			return
		}
		if req.Username == "" && req.Password == "" {
			next.ServeHTTP(response, request)
		} else {
			return
		}

	})
}
func handleError(response http.ResponseWriter, message string) {
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(map[string]string{
		"Success": "False",
		"Message": message,
	})
	fmt.Println(message)
}

func fetchDataAndForm(response http.ResponseWriter, request *http.Request) {

	var requestBody map[string]interface{}
	json.NewDecoder(request.Body).Decode(&requestBody)

	fmt.Println(requestBody)

	if requestBody == nil {
		handleError(response, "Do Provide Required Data")
		return
	}

	lowerCaseRequestBody := make(map[string]interface{})
	for key, value := range requestBody {
		lowerCaseKey := strings.ToLower(key)
		lowerCaseRequestBody[lowerCaseKey] = value
	}

	requiredKeys := []string{"id", "formid", "processdefinitionkey", "formversion"}

	for _, key := range requiredKeys {
		if _, ok := lowerCaseRequestBody[key]; !ok {
			handleError(response, "Do Provide "+key)
			return
		}
	}

	id, ok := lowerCaseRequestBody["id"].(string)
	if !ok {
		handleError(response, "Do Provide Id In String")
		return
	}
	formId, ok := lowerCaseRequestBody["formid"].(string)
	if !ok {
		handleError(response, "Do Provide formId in String")
		return
	}
	processDefinitionKey, ok := lowerCaseRequestBody["processdefinitionkey"].(string)
	if !ok {
		handleError(response, "Do Provide processdefinitionkey in String")
		return
	}

	formVersionTemp, ok := lowerCaseRequestBody["formversion"].(float64)
	if !ok {
		handleError(response, "Do Provide formVersion in Integer Format")
		return
	}
	formVersion := int(formVersionTemp)

	// if id == "" || formId == "" || processDefinitionKey == "" || formVersion == 0 {
	// 	handleError(response, "Provide Required Details")
	// 	return
	// }

	if id == "" {
		handleError(response, "Id Unavailable")
		return
	}
	if formId == "" {
		handleError(response, "FormId Unavailable")
		return
	}
	if processDefinitionKey == "" {
		handleError(response, "processDefinitionKey Unavailable")
		return
	}
	if formVersion == 0 {
		handleError(response, "formVersion Unavailable")
		return
	}
	accessToken, err := accessTokenCall()
	if err != nil || accessToken == nil {
		fmt.Println("Error Getting Token:", err)
		return
	}

	url := fmt.Sprintf("http://34.93.102.191:8082/v1/tasks/%s/variables/search", id)
	method := "POST"

	payload := strings.NewReader(``)

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	Token := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", Token)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	var taskVariable []map[string]string
	json.NewDecoder(res.Body).Decode(&taskVariable)

	extractedData := make(map[string]interface{})
	extractedData["id"] = id
	for _, value := range taskVariable {
		key := value["name"]
		data := value["value"]
		extractedData[key] = data
	}

	schemaData := fetchForm(accessToken.(string), formId, processDefinitionKey, formVersion)

	response.Header().Set("Content-Type", "application/json")
	responseData := map[string]interface{}{
		"data":   extractedData,
		"schema": schemaData,
	}
	json.NewEncoder(response).Encode(responseData)
}

func fetchForm(acessToken string, formIDD string, processDefinitionKey string, formVersion int) map[string]interface{} {
	// FormVersion := fmt.Sprintf("%.0f", formVersion)
	url := fmt.Sprintf("http://34.93.102.191:8082/v1/forms/%s?processDefinitionKey=%s&version=%v", formIDD, processDefinitionKey, formVersion)
	// fmt.Println(url)

	method := "GET"

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	Token := fmt.Sprintf("Bearer %s", acessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", Token)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error Making Request", err)
		return nil
	}
	defer res.Body.Close()

	var fetchdFormData map[string]string
	json.NewDecoder(res.Body).Decode(&fetchdFormData)

	var schemaData map[string]interface{}
	schema := fetchdFormData["schema"]
	json.Unmarshal([]byte(schema), &schemaData)
	return schemaData
}

func completeHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	Token, err := accessTokenCall()
	if err != nil {
		fmt.Println("Error Getting The Token")
	}
	defer request.Body.Close()
	var incData IncomingData
	json.NewDecoder(request.Body).Decode(&incData)

	// fmt.Println(incData)

	// json.Unmarshal(data, &incData)
	if incData.Id == "" {
		handleError(response, "Invalid Id")
		return
	}

	// if err != nil || Token == nil {
	// 	log.Println("Error:", err)
	// }
	responseData := completeTask(&incData, Token.(string))
	// fmt.Println(responseData)

	TaskState, ok := responseData["taskState"]
	if TaskState == "" && !ok {
		errorMessage, _ := responseData["message"].(string)
		handleError(response, errorMessage)
		log.Println("There is An Issue While Completing The Task")
	} else {
		log.Println("Task Completed SuccessFully")
		json.NewEncoder(response).Encode(map[string]interface{}{
			"Success": "True",
			"Message": "Task Completed SuccessFully",
			"Data":    responseData,
		})
	}

}
func completeTask(incData *IncomingData, token string) map[string]interface{} {

	id := incData.Id
	url := fmt.Sprintf("http://34.93.102.191:8082/v1/tasks/%s/complete", id)
	method := "PATCH"

	//Add Aditional BackWard Slash
	for key := range incData.Variable {
		incData.Variable[key].Value = strconv.Quote(incData.Variable[key].Value)
	}

	// fmt.Println(incData.Variable)

	x, err := json.Marshal(incData.Variable)
	if err != nil {
		fmt.Println("Error While Marshalling Data:", err)
	}

	D := "{\"variables\":" + string(x) + "}"
	reader := strings.NewReader(D)
	req, err := http.NewRequest(method, url, reader)

	if err != nil {
		fmt.Println(err)
		return nil
	}
	accessToken := fmt.Sprintf("Bearer %s", token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", accessToken)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error: Check 2", err)
		return nil
	}
	defer res.Body.Close()

	var resposneDAta map[string]interface{}
	json.NewDecoder(res.Body).Decode(&resposneDAta)
	// fmt.Println(resposneDAta)
	return resposneDAta
}

func testHandler(response http.ResponseWriter, request *http.Request) {
	var testData map[string]interface{}
	json.NewDecoder(request.Body).Decode(&testData)
	v := testData["data"].(map[string]interface{})

	var emptyMap []map[string]interface{}
	for key, value := range v {
		temp := make(map[string]interface{})
		temp["name"] = key
		temp["value"] = value
		emptyMap = append(emptyMap, temp)
	}

	// fmt.Println(emptyMap)
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(emptyMap)
}
func processHandler(response http.ResponseWriter, request *http.Request) {

	var dataToken map[string]interface{}
	json.NewDecoder(request.Body).Decode(&dataToken)

	accessToken := dataToken["access_token"].(string)

	// fmt.Println(accessToken)

	url := "http://34.93.102.191:8082/v1/internal/processes"
	method := "GET"

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	Token := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", Token)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	response.Header().Set("Content-Type", "application/json")

	defer res.Body.Close()
	var resData []map[string]interface{}
	json.NewDecoder(res.Body).Decode(&resData)

	// fmt.Println(resData)

	json.NewEncoder(response).Encode(resData)

}

type Details struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func getToken(response http.ResponseWriter, request *http.Request) {
	urll := "https://34.93.102.191:18080/auth/realms/camunda-platform/protocol/openid-connect/token"
	method := "POST"
	var reqData Details
	json.NewDecoder(request.Body).Decode(&reqData)
	fmt.Println(reqData)

	data := url.Values{}
	data.Set("client_id", "access_token")
	data.Set("client_secret", "ZBKi3qEBDKHhszZfwwiFdsvq0pMS3OvH")
	data.Set("grant_type", "password")
	data.Set("username", reqData.Username)
	data.Set("password", reqData.Password)

	req, err := http.NewRequest(method, urll, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	var tokenResponseData map[string]interface{}
	json.NewDecoder(res.Body).Decode(&tokenResponseData)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(response).Encode(map[string]interface{}{
		"access_token":  tokenResponseData["access_token"],
		"refresh_token": tokenResponseData["refresh_token"],
	})

	defer res.Body.Close()
}

/*
Working :=
--->At first we are extracting the id from the reqBody
--->Making request to /getTasks api to get all the tasks using the ID sent in Request Body
--->
*/
func tlzVariableHandler(response http.ResponseWriter, request *http.Request) {
	accessToken, err := accessTokenCall()
	if err != nil || accessToken == nil {
		fmt.Println("Error Getting Token:", err)
		return
	}
	var idBody Id
	json.NewDecoder(request.Body).Decode(&idBody)
	dataToSend := fmt.Sprintf(`{
		"assignee":"%s"
	}`, idBody.Id)
	payload := strings.NewReader(dataToSend)
	// fmt.Println(payload)
	req, err := http.NewRequest("POST", "http://34.93.102.191:8086/getTasks", payload)
	if err != nil {
		fmt.Println("Error:", err)
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}
	var resData []map[string]interface{}
	json.NewDecoder(res.Body).Decode(&resData)

	// var idP interface{}
	// var formId interface{}
	// var processDefinitionKey interface{}
	// var formVersion interface{}
	// var newReqData []map[string]interface{}
	finalResponseData := []interface{}{}

	var tempData map[string]interface{}
	// finalResponseData = append(finalResponseData, resData)
	for key, value := range resData {
		tempData = resData[key]
		// fmt.Println(tempData)
		idP := value["id"]
		fmt.Println(idP)

		url := fmt.Sprintf("http://34.93.102.191:8082/v1/tasks/%s/variables/search", idP)
		method := "POST"

		payload := strings.NewReader(``)

		req, err := http.NewRequest(method, url, payload)
		if err != nil {
			fmt.Println(err)
			return
		}

		Token := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", Token)

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer res.Body.Close()

		var resTaskVariables []map[string]string
		json.NewDecoder(res.Body).Decode(&resTaskVariables)
		// fmt.Println("Response From Api Call of Task Variables Search:==", resTaskVariables)
		extractedData := make(map[string]interface{})
		extractedData["id"] = idP
		for _, value := range resTaskVariables {
			key := value["name"]
			data := value["value"]
			extractedData[key] = data
		}
		// var newReqData map[string]interface{}
		// json.NewDecoder(res.Body).Decode(&newReqData)
		// fmt.Println(newReqData)
		// finalResponseData = append(finalResponseData, extractedData)

		for key, value := range tempData {
			extractedData[key] = value
		}

		fmt.Println(extractedData)
		finalResponseData = append(finalResponseData, extractedData)
	}
	// final=append(resData, finalResponseData)
	response.Header().Set("Content-Type", "application/json")
	// fmt.Println("Final Data Sending From Api:===", finalResponseData)
	json.NewEncoder(response).Encode(map[string]interface{}{
		"success": "true",
		"data":    finalResponseData,
	})

}
func nextFormHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	accessToken, err := accessTokenCall()
	if err != nil || accessToken == nil {
		fmt.Println("Error Getting Token:", err)
		return
	}
	bodyIoUtilData, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	reader := strings.NewReader(string(bodyIoUtilData))

	// fmt.Println(payload)
	req, err := http.NewRequest("POST", "http://34.93.102.191:8086/getTasks", reader)
	if err != nil {
		fmt.Println("Error:", err)
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}
	var resData []map[string]interface{}
	fmt.Println(resData)
	if resData == nil {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"success": "false",
			"data":    "null",
		})
		return
	}
	json.NewDecoder(res.Body).Decode(&resData)

	// var idP interface{}
	// var formId interface{}
	// var processDefinitionKey interface{}
	// var formVersion interface{}
	// var newReqData []map[string]interface{}
	finalResponseData := []interface{}{}

	var tempData map[string]interface{}
	// finalResponseData = append(finalResponseData, resData)
	for key, value := range resData {
		tempData = resData[key]
		// fmt.Println(tempData)
		idP := value["id"]
		fmt.Println(idP)

		url := fmt.Sprintf("http://34.93.102.191:8082/v1/tasks/%s/variables/search", idP)
		method := "POST"

		payload := strings.NewReader(``)

		req, err := http.NewRequest(method, url, payload)
		if err != nil {
			fmt.Println(err)
			return
		}

		Token := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", Token)

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer res.Body.Close()

		var resTaskVariables []map[string]string
		json.NewDecoder(res.Body).Decode(&resTaskVariables)
		// fmt.Println("Response From Api Call of Task Variables Search:==", resTaskVariables)
		extractedData := make(map[string]interface{})
		extractedData["id"] = idP
		for _, value := range resTaskVariables {
			key := value["name"]
			data := value["value"]
			extractedData[key] = data
		}
		// var newReqData map[string]interface{}
		// json.NewDecoder(res.Body).Decode(&newReqData)
		// fmt.Println(newReqData)
		// finalResponseData = append(finalResponseData, extractedData)

		for key, value := range tempData {
			extractedData[key] = value
		}

		fmt.Println(extractedData)
		finalResponseData = append(finalResponseData, extractedData)
	}
	// final=append(resData, finalResponseData)
	// fmt.Println("Final Data Sending From Api:===", finalResponseData)
	if finalResponseData == nil {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"success": "false",
			"data":    "null",
		})
		return
	} else {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"success": "true",
			"data":    finalResponseData,
		})
	}

}

func setPassword(Token interface{}, userId string, resPass string) *http.Response {
	url := "https://34.93.102.191:18080/auth/admin/realms/camunda-platform/users/" + userId + "/reset-password"
	method := "PUT"
	send := fmt.Sprintf(`{
		"temporary": false,
		"type": "password",
		"value": "%s"
	}`, resPass)

	payload := strings.NewReader(send)
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println("Error:", err)
	}
	accessToken := fmt.Sprintf("Bearer %s", Token)
	req.Header.Add("Authorization", accessToken)
	req.Header.Add("Content-Type", "application/json")
	respPassword, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}
	if respPassword.StatusCode == 204 {
		fmt.Println("Password set successfully")
	} else {

		fmt.Println("Failed to set password")
	}
	return respPassword
}

func RoleAssign(Token interface{}, respPassword *http.Response, userId string, response http.ResponseWriter, resPass string, incBodyData User) {
	url := "https://34.93.102.191:18080/auth/admin/realms/camunda-platform/users/" + userId + "/role-mappings/realm"
	method := "POST"
	dataToSend := `[
		{
			"id": "8ba1339f-ca96-491d-b59f-575a1d248fcd",
			"name": "Tasklist",
			"description": "Grants full access to Tasklist",
			"composite": true,
			"clientRole": false,
			"containerId": "camunda-platform"
		}
	]`

	payload := strings.NewReader(dataToSend)
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println("Error:", err)
	}
	accessToken := fmt.Sprintf("Bearer %s", Token)
	req.Header.Add("Authorization", accessToken)
	req.Header.Add("Content-Type", "application/json")
	respDatacheck, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}
	if respDatacheck.StatusCode == 204 && respPassword.StatusCode == 204 {
		//  Send Details To The User
		auth := smtp.PlainAuth("", "tprop48@gmail.com", "ovgo agtz dsdj bwhq", "smtp.gmail.com")
		to := []string{incBodyData.Email}
		msgStr := fmt.Sprintf("To: %s\r\nSubject: Your Details\r\n\r\nID:%s \r\n Password:%s\r\n", incBodyData.Email, incBodyData.FirstName, resPass)
		msg := []byte(msgStr)
		err = smtp.SendMail("smtp.gmail.com:587", auth, "tprop48@gmail.com", to, msg)
		if err != nil {
			log.Fatal(err)
		}
		json.NewEncoder(response).Encode(map[string]interface{}{
			"Success": "True",
			"Message": "Check Mail For Id And Password",
		})
		fmt.Println("Role Assigned successfully")
	} else {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"Success": "false",
			"Message": "User Created But Failed To Assign Role || Password",
		})
		fmt.Println("Failed to Assign Role")
	}
}

/*
------>
*/

func createUserHandler(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	Token, err := utils.AccessTokenCall()
	if err != nil {
		fmt.Println("Error:", err)
	}
	var incBodyData User

	//Username Generator
	// fake := faker.New()
	// username:=fake.Person().FirstName()
	// fmt.Println(username+" User Generated")

	err = json.NewDecoder(request.Body).Decode(&incBodyData)
	if err != nil {
		fmt.Println("Error", err)
	}
	url := "https://34.93.102.191:18080/auth/admin/realms/camunda-platform/users"
	method := "POST"
	dataToSend := fmt.Sprintf(`{
		"firstName": "%s",
		"lastName": "%s",
		"email": "%s",
		"enabled": true,
		"username": "%s"
	}`, incBodyData.FirstName, incBodyData.LastName, incBodyData.Email, incBodyData.FirstName)

	payload := strings.NewReader(dataToSend)

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		fmt.Println("Error:", err)
	}
	accessToken := fmt.Sprintf("Bearer %s", Token)
	req.Header.Add("Authorization", accessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
	}

	var responseCreateUser map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&responseCreateUser)
	if err != nil {
		fmt.Println("Error", err)
	}
	// fmt.Println(responseCreateUser)

	if resp.StatusCode == 201 {
		fmt.Println("User created successfully")

		//password Generator
		resPass, err := password.Generate(4, 4, 0, false, false)
		if err != nil {
			fmt.Println("Error:", err)
		}
		/*
			------------->[...........................GET THE USER ID FOR ROLE ASSIGNMENT................ ...............]
		*/
		userid, err := utils.GetUserId(incBodyData.FirstName, accessToken)
		if err != nil {
			fmt.Println("Error:", err)
		}

		userId, ok := userid.(string)
		fmt.Println(userId, "Received")

		if !ok {
			fmt.Println("Error Converting userID")
		}
		//function to set Password Of the user
		respPassword := setPassword(Token, userId, resPass)
		/*
			------------->[.............................ASSIGN ROLE OF TASKLIST..........................................]
		*/
		RoleAssign(Token, respPassword, userId, response, resPass, incBodyData)

	} else {
		json.NewEncoder(response).Encode(map[string]interface{}{
			"Success": "false",
			"Message": responseCreateUser["errorMessage"],
		})
		fmt.Println("Failed to create user")
	}

}

func main() {
	r := mux.NewRouter()
	// s := r.PathPrefix("/api").Subrouter()
	// s.Use(ValidateLogin)
	// s.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/getTasks", getTasksHandler).Methods("POST")
	r.HandleFunc("/fetchForm", fetchDataAndForm).Methods("POST")
	r.HandleFunc("/completeTask", completeHandler).Methods("POST")
	r.HandleFunc("/process", processHandler).Methods("POST")
	r.HandleFunc("/test", testHandler).Methods("POST")
	r.HandleFunc("/getToken", getToken).Methods("POST")
	r.HandleFunc("/tlzVariable", tlzVariableHandler).Methods("POST")
	r.HandleFunc("/nextForm", nextFormHandler).Methods("POST")
	r.HandleFunc("/createUser", createUserHandler).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PATCH"},
		// AllowedMethods: []string{"*"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		// AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(r)
	port := ":4005"
	s := &http.Server{
		Addr:    port,
		Handler: handler,
	}

	log.Printf("Server is Running in Port %v", port)
	log.Fatal(s.ListenAndServe())
}
