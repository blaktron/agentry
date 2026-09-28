# slack-standup-summary

Turns the standup notes you paste into one formatted Slack summary and posts it to the channel you name.

Reads the standup notes you give it and writes one Slack summary: Done, In progress, Blocked, Heads-up, using only what your notes say. It sends that message once to the channel you name through Slack's chat.postMessage, and returns the message plus whether it posted. In preview mode it returns the message without posting.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the BriefAgent's page.
