# Cycode CLI User Guide

The Cycode Command Line Interface (CLI) is an application you can install on your local machine which can scan your locally stored repositories for any secrets or infrastructure as code misconfigurations.

This guide will guide you through both installation and usage.

# Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
    1. [Install Cycode CLI](#install-cycode-cli)
        1. [Use `auth` command](#use-auth-command)
        2. [Use `configure` command](#use-configure-command)
        3. [Add to Environment Variables](#add-to-environment-variables)
            1. [On Unix/Linux](#on-unixlinux)
            2. [On Windows](#on-windows)
    2. [Install Pre-Commit Hook](#install-pre-commit-hook)
3. [Cycode Command](#cycode-command)
4. [Running a Scan](#running-a-scan)
    1. [Repository Scan](#repository-scan)
        1. [Branch Option](#branch-option)
    2. [Monitor Option](#monitor-option)
    3. [Report Option](#report-option)
    4. [Package Vulnerabilities Scan](#package-vulnerabilities-option)
        1. [License Compliance Option](#license-compliance-option)
        2. [Severity Threshold](#severity-threshold)
    5. [Path Scan](#path-scan)
        1. [Terraform Plan Scan](#terraform-plan-scan)
    6. [Commit History Scan](#commit-history-scan)
        1. [Commit Range Option](#commit-range-option)
    7. [Pre-Commit Scan](#pre-commit-scan)
5. [Scan Results](#scan-results)
    1. [Show/Hide Secrets](#showhide-secrets)
    2. [Soft Fail](#soft-fail)
    3. [Example Scan Results](#example-scan-results)
        1. [Secrets Result Example](#secrets-result-example)
        2. [IaC Result Example](#iac-result-example)
        3. [SCA Result Example](#sca-result-example)
        4. [SAST Result Example](#sast-result-example)
6. [Ignoring Scan Results](#ignoring-scan-results)
    1. [Ignoring a Secret Value](#ignoring-a-secret-value)
    2. [Ignoring a Secret SHA Value](#ignoring-a-secret-sha-value)
    3. [Ignoring a Path](#ignoring-a-path)
    4. [Ignoring a Secret, IaC, or SCA Rule](#ignoring-a-secret-iac-sca-or-sast-rule)
    5. [Ignoring a Package](#ignoring-a-package)
7. [Syntax Help](#syntax-help)

# Prerequisites

- The Cycode CLI application requires Python version 3.7 or later.
- Use the [`cycode auth` command](#use-auth-command) to authenticate to Cycode with the CLI
  - Alternatively, you can obtain a Cycode Client ID and Client Secret Key by following the steps detailed in the [Service Account Token](https://docs.cycode.com/reference/creating-a-service-account-access-token) and [Personal Access Token](https://docs.cycode.com/reference/creating-a-personal-access-token-1) pages, which contain details on obtaining these values.

# Installation

The following installation steps are applicable to both Windows and UNIX / Linux operating systems.

> :memo: **Note**<br/>
> The following steps assume the use of `python3` and `pip3` for Python-related commands; however, some systems may instead use the `python` and `pip` commands, depending on your Python environment’s configuration.

## Install Cycode CLI

To install the Cycode CLI application on your local machine, perform the following steps:

1. Open your command line or terminal application.

2. Execute the following command:

   `pip3 install cycode`

3. Navigate to the top directory of the local repository you wish to scan.

4. There are three methods to set the Cycode client ID and client secret:

   - [cycode auth](#use-auth-command) (**Recommended**)
   - [cycode configure](#use-configure-command)
   - Add them to your [environment variables](#add-to-environment-variables)

### Useing the Auth Command

> :memo: **Note**<br/>
> This is the **recommended** method for setting up your local machine to authenticate with Cycode CLI.

1. Type the following command into your terminal/command line window:

   `cycode auth`

2. A browser window will appear, asking you to log into Cycode (as seen below):

![Cycode login](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/cycode_login.png)

3. Enter your login credentials on this page and log in.

4. You will eventually be taken to the page below, where you'll be asked to choose the business group you want to authorize Cycode with (if applicable):

![authorize CLI](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/authorize_cli.png)

> :memo: **Note**<br/>
> This will be the default method for authenticating with the Cycode CLI.

5. Click the **Allow** button to authorize the Cycode CLI on the selected business group.

![allow CLI](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/allow_cli.png)

6. Once completed, you'll see the following screen, if it was selected successfully:

![successfully auth](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/successfully_auth.png)

7. In the terminal/command line screen, you will see the following when exiting the browser window:

  ```bash
  Successfully logged into cycode
  ```

### Using the Configure Command

> :memo: **Note**<br/>
> If you already set up your Cycode client ID and client secret through the Linux or Windows environment variables, those credentials will take precedent over this method.

1. Type the following command into your terminal/command line window:

   `cycode configure`

   You will see the following appear:

    ```bash
    Update credentials in file (/Users/travislloyd/.cycode/credentials.yaml)
    cycode client id []:
    ```

2. Enter your Cycode client ID value.

    ```bash
    cycode client id []: 7fe5346b-xxxx-xxxx-xxxx-55157625c72d
    ```

3. Enter your Cycode client secret value.

    ```bash
    cycode client secret []: c1e24929-xxxx-xxxx-xxxx-8b08c1839a2e
    ```

4. If the values were entered successfully, you'll see the following message:

    ```bash
    Successfully configured CLI credentials!
    ```

If you go into the `.cycode` folder under your user folder, you'll find these credentials were created and placed in the `credentials.yaml` file in that folder.

### Add to Environment Variables

#### On Unix/Linux:

```bash
export CYCODE_CLIENT_ID={your Cycode ID}
export CYCODE_CLIENT_SECRET={your Cycode Secret Key}
```

#### On Windows

1. From the Control Panel, navigate to the System menu:

![](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/image1.png)

2. Next, click Advanced system settings:

![](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/image2.png)

3. In the System Properties window that opens, click the Environment Variables button:

![](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/image3.png)

4. Create `CYCODE_CLIENT_ID` and `CYCODE_CLIENT_SECRET` variables with values matching your ID and Secret Key, respectively:

![](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/image4.png)

5. Insert the cycode.exe into the path to complete the installation.
   
## Install Pre-Commit Hook

Cycode’s pre-commit hook can be set up within your local repository so that the Cycode CLI application will identify any issues with your code automatically before you commit it to your codebase.

Perform the following steps to install the pre-commit hook:

1. Install the pre-commit framework:

   `pip3 install pre-commit`

2. Navigate to the top directory of the local repository you wish to scan.

3. Create a new YAML file named `.pre-commit-config.yaml` (include the beginning `.`) in the repository’s top directory that contains the following:

```yaml
repos:
  - repo: https://github.com/cycodehq-public/cycode-cli
    rev: stable
    hooks:
      - id: cycode
        language_version: python3
        stages:
          - commit
```

4. Install Cycode’s hook:

   `pre-commit install`

> :memo: **Note**<br/>
> A successful hook installation will result in the message:<br/>
`Pre-commit installed at .git/hooks/pre-commit`

# Cycode CLI Commands

The following are the options and commands available with the Cycode CLI application:

| Option                               | Description                                                        |
|--------------------------------------|--------------------------------------------------------------------|
| `-o`, `--output [text\|json\|table]` | Specify the output (`text`/`json`/`table`). The default is `text`. |
| `-v`, `--verbose`                    | Show detailed logs.                                                |
| `--help`                             | Show options for given command.                                    |

| Command                             | Description                                                                                                                           |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| [auth](#use-auth-command)           | Authenticates your machine to associate CLI with your Cycode account.                                                                 |
| [configure](#use-configure-command) | Initial command to authenticate your CLI client with Cycode using client ID and client secret.                                        |
| [ignore](#ingoring-scan-results)    | Ignore a specific value, path or rule ID.                                                                                             |
| [scan](#running-a-scan)             | Scan content for secrets/IaC/SCA/SAST violations. You need to specify which scan type: `ci`/`commit_history`/`path`/`repository`/etc. |
| version                             | Show the version and exit.                                                                                                            |

# Running a Scan

The Cycode CLI application offers several types of scans so that you can choose the option that best fits your case. The following are the current options and commands available:

| Option                                                     | Description                                                                                                                                                                                                                                             |
|------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-t, --scan-type [secret\|iac\|sca\|sast]`                 | Specify the scan you wish to execute (`secret`/`iac`/`sca`/`sast`), the default is `secret`                                                                                                                                                             |
| `--secret TEXT`                                            | Specify a Cycode client secret for this specific scan execution                                                                                                                                                                                         |
| `--client-id TEXT`                                         | Specify a Cycode client ID for this specific scan execution                                                                                                                                                                                             |
| `--show-secret BOOLEAN`                                    | Show secrets in plain text. See [Show/Hide Secrets](#showhide-secrets) section for more details.                                                                                                                                                        |
| `--soft-fail BOOLEAN`                                      | Run scan without failing, always return a non-error status code. See [Soft Fail](#soft-fail) section for more details.                                                                                                                                  |
| `--severity-threshold [INFO\|LOW\|MEDIUM\|HIGH\|CRITICAL]` | Show only violations at the specified level or higher (supported for the SCA scan type only).                                                                                                                                                           |
| `--sca-scan`                                               | Specify the SCA scan you wish to execute (`package-vulnerabilities`/`license-compliance`). The default is both                                                                                                                                          |
| `--monitor`                                                | When specified, the scan results will be recorded in the knowledge graph. Please note that when working in `monitor` mode, the knowledge graph will not be updated as a result of SCM events (Push, Repo creation). (Supported for SCA scan type only). |
| `--report`                                                 | When specified, a violations report will be generated. A URL link to the report will be printed as an output to the command execution                                                                                                                   |
| `--no-restore`                                             | When specified, Cycode will not run restore command. Will scan direct dependencies ONLY!                                                                                                                                                                |
| `--help`                                                   | Show options for given command.                                                                                                                                                                                                                         |

| Command                                | Description                                                     |
|----------------------------------------|-----------------------------------------------------------------|
| [commit_history](#commit-history-scan) | Scan all the commits history in this git repository             |
| [path](#path-scan)                     | Scan the files in the path supplied in the command              |
| [pre_commit](#pre-commit-scan)         | Use this command to scan the content that was not committed yet |
| [repository](#repository-scan)         | Scan git repository including its history                       |

## Repository Scan

A repository scan examines an entire local repository for any exposed secrets or insecure misconfigurations. This more holistic scan type looks at everything: the current state of your repository and its commit history. It will look not only for secrets that are currently exposed within the repository but previously deleted secrets as well.

To execute a full repository scan, execute the following:

`cycode scan repository {{path}}`

For example, consider a scenario in which you want to scan your repository stored in `~/home/git/codebase`. You could then execute the following:

`cycode scan repository ~/home/git/codebase`

The following option is available for use with this command:

| Option              | Description |
|---------------------|-------------|
| `-b, --branch TEXT` | Branch to scan, if not set scanning the default branch |

### Branch Option

To scan a specific branch of your local repository, add the argument `-b` (alternatively, `--branch`) followed by the name of the branch you wish to scan.

Consider the previous example. If you wanted to only scan a branch named `dev`, you could execute the following:

`cycode scan repository ~/home/git/codebase -b dev`

or:

`cycode scan repository ~/home/git/codebase --branch dev`

## Monitor Option

> :memo: **Note**<br/>
> This option is only available to SCA scans.

To push scan results tied to the [SCA policies](https://docs.cycode.com/docs/sca-policies) found in an SCA type scan to Cycode's knowledge graph, add the argument `--monitor` to the scan command.

Consider the following example. The following command will scan the repository for SCA policy violations and push them to Cycode:

`cycode scan -t sca --monitor repository ~/home/git/codebase`

or:

`cycode scan --scan-type sca --monitor repository ~/home/git/codebase`

When using this option, the scan results from this scan will appear in the knowledge graph, which can be found [here](https://app.cycode.com/query-builder).

> :warning: **NOTE**<br/>
> You must be an `owner` or an `admin` in Cycode to view the knowledge graph page.

## Report Option

> :memo: **Note**<br/>
> This option is only available to SCA scans.

To push scan results tied to the [SCA policies](https://docs.cycode.com/docs/sca-policies) found in the Repository scan to Cycode, add the argument `--report` to the scan command.

`cycode scan -t sca --report repository ~/home/git/codebase`

or:

`cycode scan --scan-type sca --report repository ~/home/git/codebase`

When using this option, the scan results from this scan will appear in the On-Demand Scans section of Cycode. To get to this page, click the link that appears after the printed results:

> :warning: **NOTE**<br/>
> You must be an `owner` or an `admin` in Cycode to view this page.

```bash
Scan Results: (scan_id: e04e06e5-6dd8-474f-b409-33bbee67270b)
⛔  Found issue of type: Security vulnerability in package 'vyper' referenced in project '': Multiple evaluation of contract address in call in vyper (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5

⛔  Found issue of type: Security vulnerability in package 'vyper' referenced in project '': Integer bounds error in Vyper (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5

⛔  Found issue of type: Security vulnerability in package 'pyyaml' referenced in project '': Improper Input Validation in PyYAML (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5

⛔  Found issue of type: Security vulnerability in package 'cleo' referenced in project '': cleo is vulnerable to Regular Expression Denial of Service (ReDoS) (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

2 | vyper==0.3.1
3 | cleo==1.0.0a5
4 |

⛔  Found issue of type: Security vulnerability in package 'vyper' referenced in project '': Incorrect Comparison in Vyper (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5

⛔  Found issue of type: Security vulnerability in package 'vyper' referenced in project '': Buffer Overflow in vyper (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: ./requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5

Report URL: https://app.cycode.com/on-demand-scans/617ecc3d-9ff2-493e-8be8-2c1fecaf6939
```

The report page will look something like below:

![](https://raw.githubusercontent.com/cycodehq-public/cycode-cli/main/images/scan_details.png)

## Package Vulnerabilities Option

> :memo: **Note**<br/>
> This option is only available to SCA scans.

To scan a specific package vulnerability of your local repository, add the argument `--sca-scan package-vulnerabilities` following the `-t sca` or `--scan-type sca` option.

Consider the previous example. If you wanted to only run an SCA scan on package vulnerabilities, you could execute the following:

`cycode scan -t sca --sca-scan package-vulnerabilities repository ~/home/git/codebase`

or:

`cycode scan --scan-type sca --sca-scan package-vulnerabilities repository ~/home/git/codebase`

### License Compliance Option

> :memo: **Note**<br/>
> This option is only available to SCA scans.

To scan a specific branch of your local repository, add the argument `--sca-scan license-compliance` followed by the name of the branch you wish to scan.

Consider the previous example. If you wanted to only scan a branch named `dev`, you could execute the following:

`cycode scan -t sca --sca-scan license-compliance repository ~/home/git/codebase -b dev`

or:

`cycode scan --scan-type sca --sca-scan license-compliance repository ~/home/git/codebase`

### Severity Threshold

> :memo: **Note**<br/>
> This option is only available to SCA scans.

To limit the results of the `sca` scan to a specific severity threshold, add the argument `--severity-threshold` to the scan command.

Consider the following example. The following command will scan the repository for SCA policy violations that have a severity of Medium or higher:

`cycode scan -t sca --security-threshold MEDIUM repository ~/home/git/codebase`

or:

`cycode scan --scan-type sca --security-threshold MEDIUM repository ~/home/git/codebase`

## Path Scan

A path scan examines a specific local directory and all the contents within it, instead of focusing solely on a GIT repository.

To execute a directory scan, execute the following:

`cycode scan path {{path}}`

For example, consider a scenario in which you want to scan the directory located at `~/home/git/codebase`. You could then execute the following:

`cycode scan path ~/home/git/codebase`


### Terraform Plan Scan

Cycode CLI supports Terraform plan scanning (supporting Terraform 0.12 and later)

Terraform plan file must be in JSON format (having `.json` extension)


_How to generate a Terraform plan from Terraform configuration file?_
    
1. Initialize a working directory that contains Terraform configuration file:

    `terraform init`


2. Create Terraform execution plan and save the binary output:

    `terraform plan -out={tfplan_output}`


3. Convert the binary output file into readable JSON:

    `terraform show -json {tfplan_output} > {tfplan}.json`


4. Scan your `{tfplan}.json` with Cycode CLI:

    `cycode scan -t iac path ~/PATH/TO/YOUR/{tfplan}.json`


## Commit History Scan

A commit history scan is limited to a local repository’s previous commits, focused on finding any secrets within the commit history, instead of examining the repository’s current state.

To execute a commit history scan, execute the following:

`cycode scan commit_history {{path}}`

For example, consider a scenario in which you want to scan the commit history for a repository stored in `~/home/git/codebase`. You could then execute the following:

`cycode scan commit_history ~/home/git/codebase`

The following options are available for use with this command:

| Option                    | Description |
|---------------------------|-------------|
| `-r, --commit_range TEXT` | Scan a commit range in this git repository, by default cycode scans all commit history (example: HEAD~1) |

### Commit Range Option

The commit history scan, by default, examines the repository’s entire commit history, all the way back to the initial commit. You can instead limit the scan to a specific commit range by adding the argument `--commit_range` followed by the name you specify.

Consider the previous example. If you wanted to scan only specific commits on your repository, you could execute the following:

`cycode scan commit_history -r {{from-commit-id}}...{{to-commit-id}} ~/home/git/codebase`

OR

`cycode scan commit_history --commit_range {{from-commit-id}}...{{to-commit-id}} ~/home/git/codebase`

## Pre-Commit Scan

A pre-commit scan automatically identifies any issues before you commit changes to your repository. There is no need to manually execute this scan; simply configure the pre-commit hook as detailed under the Installation section of this guide.

After your install the pre-commit hook and, you may, on occasion, wish to skip scanning during a specific commit. Simply add the following to your `git` command to skip scanning for a single commit:

`SKIP=cycode git commit -m <your commit message>`

# Scan Results

Each scan will complete with a message stating if any issues were found or not.

If no issues are found, the scan ends with the following success message:

`Good job! No issues were found!!! 👏👏👏`

If an issue is found, a `Found issue of type:` message appears upon completion instead:

```bash
⛔  Found issue of type: generic-password (rule ID: ce3a4de0-9dfc-448b-a004-c538cf8b4710) in file: config/my_config.py
Secret SHA: a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0  ⛔
0 | @@ -0,0 +1 @@
1 | +my_password = 'h3l***********350'
2 | \ No newline at end of file
```

In the event an issue is found, review the file in question for the specific line highlighted by the result message. Implement any changes required to resolve the issue, then execute the scan again.

## Show/Hide Secrets

In the above example, a secret was found in the file `secret_test`, located in the subfolder `cli`. The second part of the message shows the specific line the secret appears in, which in this case is a value assigned to `googleApiKey`.

Note how the above example obscures the actual secret value, replacing most of the secret with asterisks. Scans obscure secrets by default, but you may optionally disable this feature in order to view the full secret (assuming the machine you are viewing the scan result on is sufficiently secure from prying eyes).

To disable secret obfuscation, add the `--show-secret` argument to any type of scan, then assign it a `1` value to show the full secret in the result message, or `0` to hide the secret (which is done by default).

In the following example, a Path Scan is executed against the `cli` subdirectory with the option enabled to display any secrets found in full:

`cycode scan --show-secret=1 path ./cli`

The result would then not be obfuscated:

```bash
⛔  Found issue of type: generic-password (rule ID: ce3a4de0-9dfc-448b-a004-c538cf8b4710) in file: config/my_config.py
Secret SHA: a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0  ⛔
0 | @@ -0,0 +1 @@
1 | +my_password = 'h3110w0r1d!@#$350'
2 | \ No newline at end of file
```

## Soft Fail

Utilizing the soft fail feature will not fail the CI/CD step within the pipeline if the Cycode scan finds an issue. Additionally, in case an issue occurs from Cycode’s side, a soft fail will automatically execute to avoid interference.

Add the `--soft-fail` argument to any type of scan to configure this feature, then assign a value of `1` if you want found issues to result in a failure within the CI/CD tool or `0` for scan results to have no impact (result in a `success` result).

## Example Scan Results

### Secrets Result Example

```bash
⛔  Found issue of type: generic-password (rule ID: ce3a4de0-9dfc-448b-a004-c538cf8b4710) in file: config/my_config.py
Secret SHA: a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0  ⛔
0 | @@ -0,0 +1 @@
1 | +my_password = 'h3l***********350'
2 | \ No newline at end of file
```

### IaC Result Example

```bash
⛔  Found issue of type: Resource should use non-default namespace (rule ID: bdaa88e2-5e7c-46ff-ac2a-29721418c59c) in file: ./k8s/k8s.yaml   ⛔

7 |   name: secrets-file
8 |   namespace: default
9 |   resourceVersion: "4228"
```

### SCA Result Example

```bash
⛔  Found issue of type: Security vulnerability in package 'pyyaml' referenced in project 'Users/myuser/my-test-repo': Improper Input Validation in PyYAML (rule ID: d003b23a-a2eb-42f3-83c9-7a84505603e5) in file: Users/myuser/my-test-repo/requirements.txt   ⛔

1 | PyYAML~=5.3.1
2 | vyper==0.3.1
3 | cleo==1.0.0a5
```

### SAST Result Example

```bash
⛔  Found issue of type: Detected a request using 'http://'. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information. Use 'https://' instead. (rule ID: 3fbbd34b-b00d-4415-b9d9-f861c076b9f2) in file: ./requests.py   ⛔

2 |
3 | res = requests.get('http://example.com', timeout=1)
4 | print(res.content)
```

# Ignoring Scan Results

Ignore rules can be added to ignore specific secret values, specific SHA512 values, specific paths, and specific Cycode secret and IaC rule IDs. This will cause the scan to not alert these values. The ignore rules are written and saved locally in the `./.cycode/config.yaml` file.

> :warning: **Warning**<br/>
> Adding values to be ignored should be done with careful consideration of the values, paths, and policies to ensure that the scans will pick up true positives.

The following are the options available for the `cycode ignore` command:

| Option                          | Description |
|---------------------------------|-------------|
| `--by-value TEXT`               | Ignore a specific value while scanning for secrets. See [Ignoring a Secret Value](#ignoring-a-secret-value) for more details. |
| `--by-sha TEXT`                 | Ignore a specific SHA512 representation of a string while scanning for secrets. See [Ignoring a Secret SHA Value](#ignoring-a-secret-sha-value) for more details. |
| `--by-path TEXT`                | Avoid scanning a specific path. Need to specify scan type. See [Ignoring a Path](#ignoring-a-path) for more details. |
| `--by-rule TEXT`                | Ignore scanning a specific secret rule ID/IaC rule ID/SCA rule ID. See [Ignoring a Secret or Iac Rule](#ignoring-a-secret-or-iac-rule) for more details. |
| `--by-package TEXT`             | Ignore scanning a specific package version while running an SCA scan. Expected pattern - `name@version`. See [Ignoring a Package](#ignoring-a-package) for more details. |
| `-t, --scan-type [secret\|iac\|sca\|sast]` | Specify the scan you wish to execute (`secret`/`iac`/`sca`/`sast`), The default value is `secret` |
| `-g, --global`                  | Add an ignore rule and update it in the global `.cycode` config file |

In the following example, a pre-commit scan runs and finds the following:

```bash
⛔  Found issue of type: generic-password (rule ID: ce3a4de0-9dfc-448b-a004-c538cf8b4710) in file: config/my_config.py
Secret SHA: a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0  ⛔
0 | @@ -0,0 +1 @@
1 | +my_password = 'h3l***********350'
2 | \ No newline at end of file
```

If this is a value that is not a valid secret, then use the the `cycode ignore` command to ignore the secret by its value, SHA value, specific path, or rule ID. If this is an IaC scan, then you can ignore that result by its path or rule ID.

## Ignoring a Secret Value

To ignore a specific secret value, you will need to use the `--by-value` flag. This will ignore the given secret value from all future scans. Use the following command to add a secret value to be ignored:

`cycode ignore --by-value {{secret-value}}`

In the example at the top of this section, the command to ignore a specific secret value is as follows:

`cycode ignore --by-value h3110w0r1d!@#$350`

In the example above, replace the `h3110w0r1d!@#$350` value with your non-masked secret value. See the Cycode scan options for details on how to see secret values in the scan results.

## Ignoring a Secret SHA Value

To ignore a specific secret SHA value, you will need to use the `--by-sha` flag. This will ignore the given secret SHA value from all future scans. Use the following command to add a secret SHA value to be ignored:

`cycode ignore --by-sha {{secret-sha-value}}`

In the example at the top of this section, the command to ignore a specific secret SHA value is as follows:

`cycode ignore --by-sha a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0`

In the example above, replace the `a44081db3296c84b82d12a35c446a3cba19411dddfa0380134c75f7b3973bff0` value with your secret SHA value.

## Ignoring a Path

To ignore a specific path for either secret, IaC, or SCA scans, you will need to use the `--by-path` flag in conjunction with the `-t, --scan-type` flag (you must specify the scan type). This will ignore the given path from all future scans for the given scan type. Use the following command to add a path to be ignored:

`cycode ignore -t {{scan-type}} --by-path {{path}}`

OR

`cycode ignore --scan-type {{scan-type}} --by-path {{path}}`

In the example at the top of this section, the command to ignore a specific path for a secret is as follows:

`cycode ignore -t secret --by-path ~/home/my-repo/config`

In the example above, replace the `~/home/my-repo/config` value with your path value.

In the example at the top of this section, the command to ignore a specific path from IaC scans is as follows:

`cycode ignore -t iac --by-path ~/home/my-repo/config`

In the example above, replace the `~/home/my-repo/config` value with your path value.

In the example at the top of this section, the command to ignore a specific path from SCA scans is as follows:

`cycode ignore -t sca --by-path ~/home/my-repo/config`

In the example above, replace the `~/home/my-repo/config` value with your path value.

## Ignoring a Secret, IaC, SCA, or SAST Rule

To ignore a specific secret, IaC, SCA, or SAST rule, you will need to use the `--by-rule` flag in conjunction with the `-t, --scan-type` flag (you must specify the scan type). This will ignore the given rule ID value from all future scans. Use the following command to add a rule ID value to be ignored:

`cycode ignore -t {{scan-type}} --by-rule {{rule-ID}}`

OR

`cycode ignore --scan-type {{scan-type}} --by-rule {{rule-ID}}`

In the example at the top of this section, the command to ignore the specific secret rule ID is as follows:

`cycode ignore --scan-type secret --by-rule ce3a4de0-9dfc-448b-a004-c538cf8b4710`

In the example above, replace the `ce3a4de0-9dfc-448b-a004-c538cf8b4710` value with the rule ID you want to ignore.

In the example at the top of this section, the command to ignore the specific IaC rule ID is as follows:

`cycode ignore --scan-type iac --by-rule bdaa88e2-5e7c-46ff-ac2a-29721418c59c`

In the example above, replace the `bdaa88e2-5e7c-46ff-ac2a-29721418c59c` value with the rule ID you want to ignore.

In the example at the top of this section, the command to ignore the specific SCA rule ID is as follows:

`cycode ignore --scan-type sca --by-rule dc21bc6b-9f4f-46fb-9f92-e4327ea03f6b`

In the example above, replace the `dc21bc6b-9f4f-46fb-9f92-e4327ea03f6b` value with the rule ID you want to ignore.

## Ignoring a Package

> :memo: **Note**<br/>
> This option is only available to the SCA scans.

To ignore a specific package in the SCA scans, you will need to use the `--by-package` flag in conjunction with the `-t, --scan-type` flag (you must specify the `sca` scan type). This will ignore the given package, using the `{{package_name}}@{{package_version}}` formatting, from all future scans. Use the following command to add a package and version to be ignored:

`cycode ignore --scan-type sca --by-package {{package_name}}@{{package_version}}`

OR

`cycode ignore -t sca --by-package {{package_name}}@{{package_version}}`

In the example below, the command to ignore a specific SCA package is as follows:

`cycode ignore --scan-type sca --by-package pyyaml@5.3.1`

In the example above, replace `pyyaml` with package name and `5.3.1` with the package version you want to ignore.

# Syntax Help

You may add the `--help` argument to any command at any time to see a help message that will display available options and their syntax.

To see general help, simply enter the command:

`cycode --help`

To see scan options, enter:

`cycode scan --help`

To see the options available for a specific type of scan, enter:

`cycode scan {{option}} --help`

For example, to see options available for a Path Scan, you would simply enter:

`cycode scan path --help`

To see the options available for the ignore scan function, use this command:

`cycode ignore --help`
