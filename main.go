package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	// "io/ioutil"

	// "io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

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
	fmt.Println(accessToken)
	if err != nil || accessToken == nil {
		fmt.Println("Error In Getting Token:", err)
	}

	var idBody Id

	json.NewDecoder(request.Body).Decode(&idBody)
	if idBody.Id == "" {
		handleError(response, "Do Provide The ID")
		return
	}
	fmt.Println(idBody.Id)

	myid := idBody.Id

	url := "http://34.93.102.191:8082/v1/tasks/search"
	method := "POST"

	payload := fmt.Sprintf(`{
		"state": "CREATED",
		"assigned": true,
		"assignee": "%s"
	}`, myid)

	reader := strings.NewReader(payload)

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

	if id == ""{
		handleError(response,"Id Unavailable")
		return
	}
	if formId == ""{
		handleError(response,"FormId Unavailable")
		return
	}
	if processDefinitionKey == ""{
		handleError(response,"processDefinitionKey Unavailable")
		return
	}
	if formVersion ==0{
		handleError(response,"formVersion Unavailable")
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

	Token, err := accessTokenCall()
	if err != nil {
		fmt.Println("Error Getting The Token")
	}
	defer request.Body.Close()
	var incData IncomingData
	err = json.NewDecoder(request.Body).Decode(&incData)
	if err != nil {
		fmt.Println("Error", err)
	}

	// fmt.Println(incData)

	// json.Unmarshal(data, &incData)
	if incData.Id == "" {
		handleError(response, "Invalid Id")
		return
	}

	if err != nil || Token == nil {
		log.Println("Error:", err)
	}

	responseData := completeTask(&incData, Token.(string))
	response.Header().Set("Content-Type", "application/json")
	TaskState, ok := responseData["taskState"].(string)

	if TaskState == "" || !ok {
		errorMessage, _ := responseData["message"].(string)
		handleError(response, errorMessage)
		log.Println("Unable To Complete The Task")
	} else {
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
		fmt.Println("Error:", err)
		return nil
	}
	defer res.Body.Close()

	var resposneDAta map[string]interface{}
	json.NewDecoder(res.Body).Decode(&resposneDAta)
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
type Details struct{
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

func tlzVariable(response http.ResponseWriter,request *http.Request){
	var idBody Id 
	json.NewDecoder(request.Body).Decode(&idBody)
	dataToSend:=fmt.Sprintf(`{
		"Id":"%s"
	}`,idBody.Id)
	payload:=strings.NewReader(dataToSend)
	fmt.Println(payload)
	req,err:=http.NewRequest("POST","http://34.93.102.191:8086/getTasks",payload)
	if err!=nil{
		fmt.Println("Error:",err)
	}
	res,err:=client.Do(req)
	if err!=nil{
		fmt.Println("Error:",err)
	}
	var resData []map[string]interface{}
	json.NewDecoder(res.Body).Decode(&resData)
	
	// var idP interface{}
	// var formId interface{} 
	// var processDefinitionKey interface{} 
	// var formVersion interface{}
	// var newReqData []map[string]interface{}
	responseData := []interface{}{}
	for _,value:=range resData{
		var newReqData map[string]interface{}
		idP:=value["id"]
		formId:=value["formId"]
		processDefinitionKey:=value["processDefinitionKey"]
		formVersion:=value["formVersion"]
		// fmt.Println(idP)
		// fmt.Println(formVersion.(float64))
		if formId==nil{
			formId=""
		}
		if formVersion == nil{
			formVersion=0.0
		}

		dataToSEnd:=fmt.Sprintf(`{
			"id": "%s",
			"formId": "%s",
			"processDefinitionKey": "%s",
			"formVersion": %f
	   }`,idP,formId,processDefinitionKey,formVersion)
	//    fmt.Println(dataToSEnd)
		payload:=strings.NewReader(dataToSEnd)
		req,err:=http.NewRequest("POST","http://34.93.102.191:8086/fetchForm",payload)
		if err!=nil{
			fmt.Println("Error:",err)
		}
		res,err:=client.Do(req)
		if err!=nil{
			fmt.Println("Error:",err)
		}
		// resBody,err:=ioutil.ReadAll(res.Body)
		// fmt.Println(string(resBody))
		json.NewDecoder(res.Body).Decode(&newReqData)
		// fmt.Println(newReqData)
		responseData=append(responseData,newReqData)
	}
	response.Header().Set("Content-Type","application/json")
	// fmt.Println(responseData)
	json.NewEncoder(response).Encode(map[string]interface{}{
		"success":"true",
		"data":responseData,
	})



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
	r.HandleFunc("/getToken",getToken).Methods("POST")
	r.HandleFunc("/tlzVariable",tlzVariable).Methods("POST")


	// handler := cors.Default().Handler(r)

	// s := &http.Server{
	// 	Addr:    ":4005",
	// 	Handler: handler,
	// }

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
