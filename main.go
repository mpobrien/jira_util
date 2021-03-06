package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
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
	"text/tabwriter"
	"time"

	markdown "github.com/MichaelMure/go-term-markdown"
	"github.com/StevenACoffman/j2m"
	"github.com/andygrunwald/go-jira"
	"github.com/dghubble/oauth1"
	"github.com/mitchellh/cli"
	"golang.org/x/net/context"
)

var jiraURL = "https://jira.mongodb.org/"

func jiraHTTPClient(ctx context.Context, config *oauth1.Config) (*http.Client, error) {
	cacheFile, err := jiraTokenCacheFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get path to cached credential file: %v", err)
	}
	tok, err := jiraTokenFromFile(cacheFile)
	if err != nil {
		// cached token not available, prompt for auth code
		tok, err = jiraTokenFromWeb(config)
		if err != nil {
			return nil, fmt.Errorf("unable to get token from web: %v", err)
		}
		if err := saveJIRAToken(cacheFile, tok); err != nil {
			return nil, fmt.Errorf("unable to save token to cache file: %v", err)
		}
	}
	return config.Client(ctx, tok), nil
}

func jiraTokenFromWeb(config *oauth1.Config) (*oauth1.Token, error) {
	requestToken, requestSecret, err := config.RequestToken()
	if err != nil {
		return nil, fmt.Errorf("unable to get request token: %v", err)
	}
	authorizationURL, err := config.AuthorizationURL(requestToken)
	if err != nil {
		return nil, fmt.Errorf("unable to get authorization url: %v", err)
	}

	fmt.Println("Load the following link in your browser, then copy the authorization code and paste it below:")
	fmt.Println(authorizationURL.String())
	fmt.Printf("Authorization code: ")

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, fmt.Errorf("unable to read authorization code: %v", err)
	}

	accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, code)
	if err != nil {
		return nil, fmt.Errorf("unable to get access token: %v", err)
	}
	return oauth1.NewToken(accessToken, accessSecret), nil
}

func jiraTokenCacheFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, ".credentials")
	if err := os.MkdirAll(tokenCacheDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create credentials dir '%s': %v", tokenCacheDir, err)
	}
	return filepath.Join(tokenCacheDir, url.QueryEscape(jiraURL+".json")), err
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

func saveJIRAToken(file string, token *oauth1.Token) error {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}

func jiraClient(pkFilePath string, jiraConsumerKey string) (*jira.Client, error) {
	jiraPrivateKey, err := ioutil.ReadFile(pkFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file '%v': %v", pkFilePath, err)
	}

	ctx := context.Background()
	keyDERBlock, _ := pem.Decode([]byte(jiraPrivateKey))
	if keyDERBlock == nil {
		return nil, errors.New("unable to decode key PEM block")
	}
	if !(keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY")) {
		return nil, fmt.Errorf("unexpected key DER block type: %s", keyDERBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS1 private key. %v", err)
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
	httpClient, err := jiraHTTPClient(ctx, &config)
	if err != nil {
		return nil, fmt.Errorf("unable to create new JIRA client. %v", err)
	}
	jiraClient, err := jira.NewClient(httpClient, jiraURL)
	if err != nil {
		return nil, fmt.Errorf("unable to create new JIRA client. %v", err)
	}
	return jiraClient, nil
}

func FindIssues(client *jira.Client, query string) ([]jira.Issue, error) {
	last := 0
	var issues []jira.Issue
	for {
		opt := &jira.SearchOptions{
			MaxResults: 1000, // Max results can go up to 1000
			StartAt:    last,
		}

		chunk, resp, err := client.Issue.Search(query, opt)
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

type baseCommand struct {
	PrivateKeyPath string
	ConsumerKey    string
}

func (cmdBase *baseCommand) addFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&cmdBase.PrivateKeyPath, "privateKeyPath", "", "")
	flagSet.StringVar(&cmdBase.ConsumerKey, "consumerKey", "", "")
}

func (cmdBase *baseCommand) validate() error {
	if cmdBase.ConsumerKey == "" {
		return errors.New("'consumerKey' flag is required")
	}
	if cmdBase.PrivateKeyPath == "" {
		return errors.New("'privateKeyPath' flag is required")
	}
	return nil
}

type branchLine struct {
	Raw             string
	MatchedIssueKey string
}

type searchCommand struct {
	baseCommand
	URLColumn bool
}

func (cmd *searchCommand) Help() string {
	return ""
}
func (cmd *searchCommand) Synopsis() string {
	return ``
}

// searchCommandFactory returns an empty searchCommand
func searchCommandFactory() (cli.Command, error) {
	return &searchCommand{}, nil
}

func (cmd *searchCommand) Run(args []string) int {
	set := flag.NewFlagSet("search", flag.ExitOnError)
	cmd.baseCommand.addFlags(set)
	set.BoolVar(&cmd.URLColumn, "urlColumn", true, "")

	err := set.Parse(args)
	if err != nil {
		log.Printf("error parsing flags: %v", err)
		return 1
	}
	if err := cmd.baseCommand.validate(); err != nil {
		log.Printf("error parsing flags: %v", err)
		return 1
	}

	if len(set.Args()) != 1 {
		log.Printf("search string required")
		log.Printf(cmd.Help())
		return 1
	}
	searchString := set.Args()[0]
	cli, err := jiraClient(cmd.PrivateKeyPath, cmd.ConsumerKey)
	if err != nil {
		log.Printf("failed to create jira client: %v", err)
		return 1
	}
	issues, err := FindIssues(cli, searchString)
	if err != nil {
		log.Printf(fmt.Sprintf("query failed: %v", err))
		return 1
	}
	out := tabwriter.NewWriter(
		os.Stdout,
		0,
		0,
		3,
		' ',
		0, //tabwriter.Debug,
	)
	headers := []string{
		"Issue",
		"Status",
		"Summary",
	}
	dividers := []string{}
	for _, header := range headers {
		dividers = append(dividers, strings.Repeat("-", len(header)))
	}
	fmt.Fprintln(out, strings.Join(headers, "\t"))
	fmt.Fprintln(out, strings.Join(dividers, "\t"))
	for _, issue := range issues {
		issueCol := issue.Key
		if cmd.URLColumn {
			issueCol = fmt.Sprintf("%sbrowse/%s", jiraURL, issue.Key)
		}

		fields := []string{
			issueCol,
			issue.Fields.Status.Name,
			issue.Fields.Summary,
		}

		fmt.Fprintln(
			out,
			strings.Join(fields, "\t"),
		)
	}
	out.Flush()
	return 0

}

type ticketCommand struct {
	baseCommand
}

func (cmd *ticketCommand) Help() string {
	return ""
}
func (cmd *ticketCommand) Synopsis() string {
	return ``
}

// ticketCommandFactory returns an empty ticketCommand
func ticketCommandFactory() (cli.Command, error) {
	return &ticketCommand{}, nil
}

func (cmd *ticketCommand) Run(args []string) int {
	set := flag.NewFlagSet("tickets", flag.ExitOnError)
	cmd.baseCommand.addFlags(set)
	err := set.Parse(args)
	if err != nil {
		log.Printf("error parsing flags: %v", err)
		return 1
	}
	ticketIDs := []string{}
	for i := 0; i < set.NArg(); i++ {
		ticketIDs = append(ticketIDs, set.Arg(i))
	}

	cli, err := jiraClient(cmd.PrivateKeyPath, cmd.ConsumerKey)
	if err != nil {
		log.Printf("failed to create jira client: %v", err)
		return 1
	}
	query := fmt.Sprintf("key in (%s)", strings.Join(ticketIDs, ","))
	issues, err := FindIssues(cli, query)
	if err != nil {
		log.Fatal(err)
		return 1
	}
	issuesByKey := map[string]jira.Issue{}
	for _, issue := range issues {
		issuesByKey[issue.Key] = issue
	}
	stdoutLogger := log.New(os.Stdout, "", 0)
	for key, issue := range issuesByKey {
		stdoutLogger.Print()
		stdoutLogger.Printf("%s: %s", key, issue.Fields.Summary)
		stdoutLogger.Print()
		stdoutLogger.Printf("Reporter: %s", StringifyUser(issue.Fields.Reporter))
		stdoutLogger.Printf("Assignee: %s", StringifyUser(issue.Fields.Assignee))
		stdoutLogger.Print()
		stdoutLogger.Printf("Created: %s", time.Time(issue.Fields.Created))
		stdoutLogger.Printf("Updated: %s", time.Time(issue.Fields.Updated))
		stdoutLogger.Print()
		stdoutLogger.Print("Description:")
		descMarkdown := j2m.JiraToMD(issue.Fields.Description)
		rendered := markdown.Render(descMarkdown, 80, 6)
		stdoutLogger.Print(string(rendered))
		stdoutLogger.Print()
		//os.Stdout.WriteString(rendered)

		/*
			Expand                        string            `json:"expand,omitempty" structs:"expand,omitempty"`
			Type                          IssueType         `json:"issuetype,omitempty" structs:"issuetype,omitempty"`
			Project                       Project           `json:"project,omitempty" structs:"project,omitempty"`
			Resolution                    *Resolution       `json:"resolution,omitempty" structs:"resolution,omitempty"`
			Priority                      *Priority         `json:"priority,omitempty" structs:"priority,omitempty"`
			Resolutiondate                Time              `json:"resolutiondate,omitempty" structs:"resolutiondate,omitempty"`
			Created                       Time              `json:"created,omitempty" structs:"created,omitempty"`
			Duedate                       Date              `json:"duedate,omitempty" structs:"duedate,omitempty"`
			Watches                       *Watches          `json:"watches,omitempty" structs:"watches,omitempty"`
			Assignee                      *User             `json:"assignee,omitempty" structs:"assignee,omitempty"`
			Updated                       Time              `json:"updated,omitempty" structs:"updated,omitempty"`
			Description                   string            `json:"description,omitempty" structs:"description,omitempty"`
			Summary                       string            `json:"summary,omitempty" structs:"summary,omitempty"`
			Creator                       *User             `json:"Creator,omitempty" structs:"Creator,omitempty"`
			Reporter                      *User             `json:"reporter,omitempty" structs:"reporter,omitempty"`
			Components                    []*Component      `json:"components,omitempty" structs:"components,omitempty"`
			Status                        *Status           `json:"status,omitempty" structs:"status,omitempty"`
			Progress                      *Progress         `json:"progress,omitempty" structs:"progress,omitempty"`
			AggregateProgress             *Progress         `json:"aggregateprogress,omitempty" structs:"aggregateprogress,omitempty"`
			TimeTracking                  *TimeTracking     `json:"timetracking,omitempty" structs:"timetracking,omitempty"`
			TimeSpent                     int               `json:"timespent,omitempty" structs:"timespent,omitempty"`
			TimeEstimate                  int               `json:"timeestimate,omitempty" structs:"timeestimate,omitempty"`
			TimeOriginalEstimate          int               `json:"timeoriginalestimate,omitempty" structs:"timeoriginalestimate,omitempty"`
			Worklog                       *Worklog          `json:"worklog,omitempty" structs:"worklog,omitempty"`
			IssueLinks                    []*IssueLink      `json:"issuelinks,omitempty" structs:"issuelinks,omitempty"`
			Comments                      *Comments         `json:"comment,omitempty" structs:"comment,omitempty"`
			FixVersions                   []*FixVersion     `json:"fixVersions,omitempty" structs:"fixVersions,omitempty"`
			AffectsVersions               []*AffectsVersion `json:"versions,omitempty" structs:"versions,omitempty"`
			Labels                        []string          `json:"labels,omitempty" structs:"labels,omitempty"`
			Subtasks                      []*Subtasks       `json:"subtasks,omitempty" structs:"subtasks,omitempty"`
			Attachments                   []*Attachment     `json:"attachment,omitempty" structs:"attachment,omitempty"`
			Epic                          *Epic             `json:"epic,omitempty" structs:"epic,omitempty"`
			Sprint                        *Sprint           `json:"sprint,omitempty" structs:"sprint,omitempty"`
			Parent                        *Parent           `json:"parent,omitempty" structs:"parent,omitempty"`
			AggregateTimeOriginalEstimate int               `json:"aggregatetimeoriginalestimate,omitempty" structs:"aggregatetimeoriginalestimate,omitempty"`
			AggregateTimeSpent            int               `json:"aggregatetimespent,omitempty" structs:"aggregatetimespent,omitempty"`
			AggregateTimeEstimate         int               `json:"aggregatetimeestimate,omitempty" structs:"aggregatetimeestimate,omitempty"`
			Unknowns                      tcontainer.MarshalMap
		*/
	}
	return 0
}

type ticketsCommand struct {
	baseCommand
}

func (cmd *ticketsCommand) Help() string {
	return ""
}
func (cmd *ticketsCommand) Synopsis() string {
	return `reads "git branch" data via stdin and writes it to stdout with additional summary information about tickets in jira`
}

// ticketsCommandFactory returns an empty ticketsCommand
func ticketsCommandFactory() (cli.Command, error) {
	return &ticketsCommand{}, nil
}

func (cmd *ticketsCommand) Run(args []string) int {
	set := flag.NewFlagSet("tickets", flag.ExitOnError)
	cmd.baseCommand.addFlags(set)
	err := set.Parse(args)
	if err != nil {
		log.Printf("error parsing flags: %v", err)
		return 1
	}

	if err := cmd.baseCommand.validate(); err != nil {
		log.Printf("error parsing flags: %v", err)
		return 1
	}

	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
		return 1
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
		cli, err := jiraClient(cmd.PrivateKeyPath, cmd.ConsumerKey)
		if err != nil {
			log.Printf("failed to create jira client: %v", err)
			return 1
		}
		query := fmt.Sprintf("key in (%s)", strings.Join(issueKeys, ","))
		issues, err := FindIssues(cli, query)
		if err != nil {
			log.Fatal(err)
			return 1
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
	return 0
}

func StringifyUser(user *jira.User) string {
	if user == nil {
		return "<None>"
	}
	return fmt.Sprintf("%s <%s>", user.DisplayName, user.Name)
}

func main() {
	c := cli.NewCLI("jirautil", "1.0.0")
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"ticket":  ticketCommandFactory,
		"tickets": ticketsCommandFactory,
		"search":  searchCommandFactory,
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	os.Exit(exitStatus)

}
