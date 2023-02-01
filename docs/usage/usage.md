# Quickstart


## Write a simple manifest

Here, we'll just create a simple manifest with one resource, an S3 bucket.

```yaml
version: "1"
resources:
  buckets:
    mybucket:
      bucket_name: "hello-iae"
```


## Deploy a CDK app using the manifest


IAE is built on top of AWS CDK, so if you haven't already, you'll want to [install the AWS CDK](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html).

<details>
<summary>start cdk app project</summary>

```bash
mkdir myproject
cd myproject
cdk init --language=python app
```

Next, activate the virtualenv (`.venv` by default) created by the cdk and install `iae`


=== "Linux/MacOS"
    ```bash
    source .venv/bin/activate
    pip install iae
    ```

=== "Windows"
    .venv\Scripts\activate
    pip install iae

</details>


In a typical CDK app, normally you might have something like this:


```python
import aws_cdk as cdk
app = cdk.App()

class MyStack(cdk.Stack):
    def __init__(self, scope, id, **kwargs):
        super().__init__(scope, id, **kwargs)
        # start defining constructs here

# ...

production = cdk.Environment(account='abc123', region='us-east-1')
stack = MyStack(app, 'mystack', env=production)

app.synth()
```



In `iae`, you'll do something similar, but we will instantiate our stack and describe our environment slightly differently:

```python
import aws_cdk as cdk
from level4 import ManifestStack, EnvironmentProvider
app = cdk.App()
class MyStack(ManifestStack):
    ...

production = EnvironmentProvider(environment_name='production', account='abc213', region='us-east-1')

stack = MyStack.from_manifest_file(app, 'path/to/mymanifest.iae.yaml', provider=production)

app.synth()
```

We can synth/diff/deploy/destroy your stack, just like any other CDK app.

```bash
cdk synth
```
