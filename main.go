// package main

// import (
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"net/http"
// 	"os"

// 	"github.com/joho/godotenv"
// 	"golang.org/x/oauth2"
// 	"golang.org/x/oauth2/gitlab"
// )

// func init() {
// 	if err := godotenv.Load(); err != nil {
// 		log.Fatal("No .env file found")
// 	}
// }

// func main() {
// 	//Simply returns a link to the login route
// 	http.HandleFunc("/", rootHandler)

// 	// Login route
// 	http.HandleFunc("/users/auth/gitlab/", gitlabLoginHandler)

// 	//Gitlab Callback
// 	http.HandleFunc("/users/auth/gitlab/callback", gitlabCallbackHandler)

// 	//Route where the authenticated user is redirected to
// 	http.HandleFunc("/loggedin", func(w http.ResponseWriter, r *http.Request) {
// 		loggedinHandler(w, r, "")
// 	})

// 	fmt.Println("[ UP ON PORT 3030]")
// 	log.Panic(
// 		http.ListenAndServe(":3030", nil),
// 	)
// }

// func loggedinHandler(w http.ResponseWriter, r *http.Request, gitlabData string) {
// 	if gitlabData == "" {
// 		//uUnautorized users get an unauthorized message
// 		fmt.Fprintf(w, "UNAUTHORIZED!")
// 		return
// 	}

// 	//Set return type JSON
// 	w.Header().Set("Content-type", "application/json")

// 	//Prettifying the json
// 	var prettyJSON bytes.Buffer
// 	// json.indent is a library utility function to prettify JSON indentation
// 	parserr := json.Indent(&prettyJSON, []byte(gitlabData), "", "\t")
// 	if parserr != nil {
// 		log.Panic("Error prettifying JSON:", parserr)
// 	}

// 	//Return the prettified JSON as a string
// 	fmt.Fprint(w, prettyJSON.String())
// }

// func rootHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Fprintf(w, `
// 	<!DOCTYPE html>
// <html>
//   <body>
//     <a
//       href="https://github.com/login/oauth/authorize?client_id=9586acbb28d721f5fe6735b72203eabd0da7941bf9e23aad64161147d58b6a38&redirect_uri=http://localhost:3030/users/auth/gitlab/callback"
//     >
//       Login with github
//     </a>
//   </body>
// </html>

// 	`)
// }

// func getGitlabClientID() string {
// 	gitlabClientID, exists := os.LookupEnv("CLIENT_ID")
// 	if !exists {
// 		log.Fatal("Gitlab Client ID not defined in .env file")
// 	}

// 	return gitlabClientID
// }

// func getGitlabClientSecret() string {
// 	gitlabClientSecret, exists := os.LookupEnv("CLIENT_SECRET")
// 	if !exists {
// 		log.Fatal("Gitlab Client Secret not defined in .env file")
// 	}
// 	return gitlabClientSecret
// }

// func gitlabLoginHandler(w http.ResponseWriter, r *http.Request) {
// 	//Get the environment variable
// 	gitlabClientID := getGitlabClientID()
// 	gitlabClientSecret := getGitlabClientSecret()

// 	gitlabOauth2Config := &oauth2.Config{
// 		ClientID:     gitlabClientID,
// 		ClientSecret: gitlabClientSecret,
// 		Endpoint:     gitlab.Endpoint,
// 		RedirectURL:  "http://localhost:3030/users/auth/gitlab/callback",
// 		Scopes:       []string{"read_user", "read_repository"},
// 	}
// 	authURL := gitlabOauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
// 	// log.Println("Redirecting to GitLab for authorization:", authURL)

// 	http.Redirect(w, r, authURL, http.StatusSeeOther)

// }

// func gitlabCallbackHandler(w http.ResponseWriter, r *http.Request) {
// 	code := r.URL.Query().Get("code")
// 	log.Println("GitLab Authorization Code:", code)

// 	// Step 1: Request GitLab Access Token
// 	gitlabAccessToken, err := getGitlabAccessToken(code)
// 	if err != nil {
// 		log.Panic("Error getting GitLab Access Token:", err)
// 		http.Error(w, "Error getting GitLab Access Token", http.StatusInternalServerError)
// 		return
// 	}
// 	// log.Println("GitLab Access Token:", gitlabAccessToken)

// 	// Step 2: Request GitLab User Data
// 	gitlabData, err := getGitlabData(gitlabAccessToken)
// 	if err != nil {
// 		log.Panic("Error getting GitLab User Data:", err)
// 		http.Error(w, "Error getting GitLab User Data", http.StatusInternalServerError)
// 		return
// 	}
// 	// log.Println("GitLab Data:", gitlabData)

// 	// Step 3: Handle the logged-in user
// 	loggedinHandler(w, r, gitlabData)
// }

// func getGitlabAccessToken(code string) (string, error) {
// 	clientID := getGitlabClientID()
// 	clientSecret := getGitlabClientSecret()

// 	//Set us the request body as JSON
// 	requestBodyMap := map[string]string{
// 		"client_id":     clientID,
// 		"client_secret": clientSecret,
// 		"code":          code,
// 	}
// 	requestJSON, err := json.Marshal(requestBodyMap)
// 	if err != nil {
// 		log.Println("Error marshaling JSON:", err)
// 		return "", err
// 	}

// 	// POST request to GitLab for access token
// 	req, err := http.NewRequest("POST", "http://gitlab.com/login/oauth/token", bytes.NewBuffer(requestJSON))
// 	if err != nil {
// 		log.Println("Error creating HTTP request:", err)
// 		return "", err
// 	}
// 	defer req.Body.Close()

// 	req.Header.Set("Content-Type", "application/json")

// 	//Get the response
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		log.Println("Error making HTTP request:", err)
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// Read the response body
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Println("Error reading response body:", err)
// 		return "", err
// 	}

// 	// log.Println("GitLab Access Token Request Body:", string(requestJSON))
// 	// log.Println("GitLab Access Token Response Status:", resp.Status)
// 	// log.Println("GitLab Access Token Response Body:", string(respBody))

// 	// Log the GitLab response for debugging
// 	// log.Println("GitLab Response:", string(respBody))

// 	// Check for errors in the GitLab response
// 	if resp.StatusCode != http.StatusOK {
// 		log.Println("GitLab Access Token Error:", resp.Status)
// 		return "", fmt.Errorf("GitLab API returned an error: %s", resp.Status)
// 	}

// 	//Represents the response received from gitlab
// 	type gitlabAccessTokenResponse struct {
// 		AccessToken string `json:"access_token"`
// 		TokenType   string `json:"token_type"`
// 		Scope       string `json:"scope"`
// 	}

// 	// Parse JSON response
// 	var gitlabResp gitlabAccessTokenResponse
// 	if err := json.Unmarshal(respBody, &gitlabResp); err != nil {
// 		log.Println("Error unmarshaling JSON:", err)
// 		return "", err
// 	}

// 	return gitlabResp.AccessToken, nil
// }

// func getGitlabData(accessToken string) (string, error) {
// 	// Get request to a set URL
// 	req, err := http.NewRequest("GET", "http://gitlab.com/api/v4/user", nil)
// 	if err != nil {
// 		return "", err
// 	}
// 	// Set the Authorization header before sending the request
// 	// Authorization: token XXXXXXXXXXXXXXXXXXXXXXXXXXX
// 	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
// 	req.Header.Set("Authorization", authorizationHeaderValue)

// 	// Make the request
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	// Print the response status code
// 	// log.Println("GitLab User Data Response Status Code:", resp.StatusCode)

// 	// Read the response body
// 	respBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}

// 	// log.Println("GitLab User Data Response:", string(respBody))

// 	// Check if the response is successful (HTTP status 200)
// 	// if resp.StatusCode != http.StatusOK {
// 	// 	return "", fmt.Errorf("GitLab API returned an error: %s", resp.Status)
// 	// }

// 	return string(respBody), nil
// }
package main