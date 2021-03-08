package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/andygrunwald/go-jira"
	"github.com/dghubble/oauth1"
	"golang.org/x/net/context"
)

var jiraURL = "https://jira.mongodb.org/"

const jiraPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
put the key here
-----END RSA PRIVATE KEY-----`

const jiraConsumerKey = "put the consumer key here"

func getJIRAHTTPClient(ctx context.Context, config *oauth1.Config) *http.Client {
	cacheFile, err := jiraTokenCacheFile()
	if err != nil {
		log.Fatalf("Unable to get path to cached credential file. %v", err)
	}
	tok, err := jiraTokenFromFile(cacheFile)
	if err != nil {
		tok = getJIRATokenFromWeb(config)
		saveJIRAToken(cacheFile, tok)
	}
	return config.Client(ctx, tok)
}

func getJIRATokenFromWeb(config *oauth1.Config) *oauth1.Token {
	requestToken, requestSecret, err := config.RequestToken()
	if err != nil {
		log.Fatalf("Unable to get request token. %v", err)
	}
	authorizationURL, err := config.AuthorizationURL(requestToken)
	if err != nil {
		log.Fatalf("Unable to get authorization url. %v", err)
	}
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authorizationURL.String())

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code. %v", err)
	}

	accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, code)
	if err != nil {
		log.Fatalf("Unable to get access token. %v", err)
	}
	return oauth1.NewToken(accessToken, accessSecret)
}

func jiraTokenCacheFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, ".credentials")
	os.MkdirAll(tokenCacheDir, 0700)
	return filepath.Join(tokenCacheDir,
		url.QueryEscape(jiraURL+".json")), err //TODO
}

func jiraTokenFromFile(file string) (*oauth1.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := &oauth1.Token{}
	err = json.NewDecoder(f).Decode(t)
	defer f.Close()
	return t, err
}

func saveJIRAToken(file string, token *oauth1.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func getJIRAClient() *jira.Client {
	ctx := context.Background()
	keyDERBlock, _ := pem.Decode([]byte(jiraPrivateKey))
	if keyDERBlock == nil {
		log.Fatal("unable to decode key PEM block")
	}
	if !(keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY")) {
		log.Fatalf("unexpected key DER block type: %s", keyDERBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatalf("unable to parse PKCS1 private key. %v", err)
	}
	config := oauth1.Config{
		ConsumerKey: jiraConsumerKey,
		CallbackURL: "oob", /* for command line usage */
		Endpoint: oauth1.Endpoint{
			RequestTokenURL: jiraURL + "plugins/servlet/oauth/request-token",
			AuthorizeURL:    jiraURL + "plugins/servlet/oauth/authorize",
			AccessTokenURL:  jiraURL + "plugins/servlet/oauth/access-token",
		},
		Signer: &oauth1.RSASigner{
			PrivateKey: privateKey,
		},
	}
	jiraClient, err := jira.NewClient(getJIRAHTTPClient(ctx, &config), jiraURL)
	if err != nil {
		log.Fatalf("unable to create new JIRA client. %v", err)
	}
	return jiraClient
}

func GetAllIssues(client *jira.Client, searchString string) ([]jira.Issue, error) {
	last := 0
	var issues []jira.Issue
	for {
		opt := &jira.SearchOptions{
			MaxResults: 1000, // Max results can go up to 1000
			StartAt:    last,
		}

		chunk, resp, err := client.Issue.Search(searchString, opt)
		if err != nil {
			return nil, err
		}

		total := resp.Total
		if issues == nil {
			issues = make([]jira.Issue, 0, total)
		}
		issues = append(issues, chunk...)
		last = resp.StartAt + len(chunk)
		if last >= total {
			return issues, nil
		}
	}
}

type branchLine struct {
	Raw             string
	MatchedIssueKey string
}

func main() {
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	issueRegex := regexp.MustCompile(`^(\w+-\d+)(-\w+)?`)
	inputLines := strings.Split(string(input), "\n")

	branchLines := make([]branchLine, 0, len(inputLines))
	issueKeys := []string{}
	for _, line := range inputLines {
		newBranchLine := branchLine{Raw: line}
		lineParts := strings.Fields(line)
		if len(lineParts) == 0 {
			continue
		}
		match := issueRegex.FindStringSubmatch(lineParts[0])
		if len(match) > 0 {
			matchedIssueKey := strings.ToUpper(match[1])
			issueKeys = append(issueKeys, fmt.Sprintf(`"%s"`, matchedIssueKey))
			newBranchLine.MatchedIssueKey = matchedIssueKey
		}
		branchLines = append(branchLines, newBranchLine)
	}

	issuesByKey := map[string]jira.Issue{}
	if len(issueKeys) > 0 {
		cli := getJIRAClient()
		query := fmt.Sprintf("key in (%s)", strings.Join(issueKeys, ","))
		issues, err := GetAllIssues(cli, query)
		if err != nil {
			log.Fatal(err)
		}
		for _, issue := range issues {
			issuesByKey[issue.Key] = issue
		}
	}

	for _, outputLine := range branchLines {
		matchedIssue, ok := issuesByKey[outputLine.MatchedIssueKey]
		if !ok {
			fmt.Println(outputLine.Raw)
			continue
		}
		fmt.Printf("%s\t%s\n", outputLine.Raw, matchedIssue.Fields.Summary)
	}
}
