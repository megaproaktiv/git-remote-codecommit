# AWS Codecommit helper

CodeCommit is deprecated, but existing repositories remain.

The AWS build helper
"https://github.com/aws/git-remote-codecommit/tree/master"
is not working any more, because python has not backward compatibility.

So I let a model translate it to go.
Tested for clone, pull, push.

G.Glawe Juli 2025

## Installation

Copy the binary into a executable location.
Git should automatically use it.

With authenticated AWS credentials in a profile you can use:


```bash
git clone codecommit://demo-profile@MyRepositoryName
```
