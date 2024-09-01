# Rust Payment API CDK

## Getting Started

### Installing AWS CDK CLI

```
sudo npm install -g aws-cdk
```

### Install NPM Dependencies

```
npm install
```

### Synthesizing CF Stacks (Not required for deploying)

```
cdk synth
```

### Deploying Stacks

```
cdk deploy STACK_NAME
```

To deploy all stacks use the following command:

```
cdk deploy --all
```

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
