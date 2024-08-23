# Quickstart



## Prerequisites

Level4 is built on top of AWS CDK, so if you haven't already, you'll want to install nodejs and [install the AWS CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html)

```bash
npm install -g aws-cdk
```

You will also need an AWS account and have your credentials configured


### Install level4

`level4` can be installed using `pip`.

```bash
pip install level4
```


## Start a new project

Starting a new level4 project is very similar to starting a CDK project (under the hood, it really is a CDK project).

```
mkdir myproject
cd myproject
python -m level4 init
```


Next, activate the virtualenv (`.venv` by default) that was created in your project directory


=== "Linux/MacOS"
    ```bash
    source .venv/bin/activate
    ```

=== "Windows"
    ```powershell
    .venv\Scripts\activate
    ```
