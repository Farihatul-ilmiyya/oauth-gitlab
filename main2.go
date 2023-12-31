package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/gitlab"
)

var (
	gitlabOauthConfig = &oauth2.Config{
		ClientID:     "9586acbb28d721f5fe6735b72203eabd0da7941bf9e23aad64161147d58b6a38",
		ClientSecret: "gloas-69ea2f7e3f1ae0fdfeeb68ae0445610edb3c2c5a036887df365bba8824f97ca0",
		RedirectURL:  "http://localhost:3030/users/auth/gitlab/callback",
		Endpoint:     gitlab.Endpoint,
		Scopes:       []string{"read_user"},
	}
	gitlabAPI = "https://gitlab.com/api/v4"

	oauthStateString = "random_string"
)

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/users/auth/gitlab/callback", handleCallback)

	fmt.Println("Server running on :3030")
	http.ListenAndServe(":3030", nil)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the OAuth GitLab Example")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := gitlabOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("Invalid OAuth State")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	token, err := gitlabOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Error exchanging code for token: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	user, err := getCurrentUser(token.AccessToken)
	if err != nil {
		fmt.Printf("getCurrentUser: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	client := gitlabOauthConfig.Client(context.Background(), token)

	userInfo, err := getUserInfo(client)
	if err != nil {
		fmt.Printf("Error getting user info: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Println(user)
	fmt.Println(userInfo)
	fmt.Fprintf(w, "GitLab OAuth Token: %s", token.AccessToken)
}

func getCurrentUser(accessToken string) (*GitLabUser, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", gitlabAPI+"/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(body))
	var user GitLabUser
	// err = json.Unmarshal(body, &user)
	// if err != nil {
	// 	return nil, err
	// }

	return &user, nil
}

type GitLabUser struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func getUserInfo(client *http.Client) (*UserInfo, error) {
	response, err := client.Get("https://gitlab.com/api/v4/user")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var userInfo UserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}
	PrettyPrint(userInfo)
	return &userInfo, nil
}
func PrettyPrint(i interface{}) {
	s, _ := json.MarshalIndent(i, "", "\t")
	fmt.Println(string(s))
}

// Generated by https://quicktype.io

type UserInfo struct {
	ID                             int64         `json:"id"`
	Username                       string        `json:"username"`
	Name                           string        `json:"name"`
	State                          string        `json:"state"`
	Locked                         bool          `json:"locked"`
	AvatarURL                      string        `json:"avatar_url"`
	WebURL                         string        `json:"web_url"`
	CreatedAt                      string        `json:"created_at"`
	Bio                            string        `json:"bio"`
	Location                       string        `json:"location"`
	PublicEmail                    interface{}   `json:"public_email"`
	Skype                          string        `json:"skype"`
	Linkedin                       string        `json:"linkedin"`
	Twitter                        string        `json:"twitter"`
	Discord                        string        `json:"discord"`
	WebsiteURL                     string        `json:"website_url"`
	Organization                   string        `json:"organization"`
	JobTitle                       string        `json:"job_title"`
	Pronouns                       interface{}   `json:"pronouns"`
	Bot                            bool          `json:"bot"`
	WorkInformation                interface{}   `json:"work_information"`
	LocalTime                      interface{}   `json:"local_time"`
	LastSignInAt                   string        `json:"last_sign_in_at"`
	ConfirmedAt                    string        `json:"confirmed_at"`
	LastActivityOn                 string        `json:"last_activity_on"`
	Email                          string        `json:"email"`
	ThemeID                        int64         `json:"theme_id"`
	ColorSchemeID                  int64         `json:"color_scheme_id"`
	ProjectsLimit                  int64         `json:"projects_limit"`
	CurrentSignInAt                string        `json:"current_sign_in_at"`
	Identities                     []interface{} `json:"identities"`
	CanCreateGroup                 bool          `json:"can_create_group"`
	CanCreateProject               bool          `json:"can_create_project"`
	TwoFactorEnabled               bool          `json:"two_factor_enabled"`
	External                       bool          `json:"external"`
	PrivateProfile                 bool          `json:"private_profile"`
	CommitEmail                    string        `json:"commit_email"`
	SharedRunnersMinutesLimit      interface{}   `json:"shared_runners_minutes_limit"`
	ExtraSharedRunnersMinutesLimit interface{}   `json:"extra_shared_runners_minutes_limit"`
	ScimIdentities                 []interface{} `json:"scim_identities"`
}
