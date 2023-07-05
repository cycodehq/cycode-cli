import requests

requests.get('https://slack.com/api/conversations.list', verify=False)  # noqa: S113, S501
