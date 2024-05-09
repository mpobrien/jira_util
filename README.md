### Setup


First, you need to get a jira OAuth token.
Do the following:
```shell
git clone git@github.com:10gen/iteng-jira-oauth
cd iteng-jira-oauth
virtualenv ./venv
source ./venv/bin/activate
pip3 install -r requirements.txt
python3 jira-token-gen.py
```

Then follow the instructions in the terminal.

Take the private key that is sent back and save it to a file.
Then the consumer key and use it in the following command:

```
jirabranch search -consumerKey <consumerKey> -privateKeyPath <path-to-PK-file> 'project = PROJECT and resolution is empty'```
