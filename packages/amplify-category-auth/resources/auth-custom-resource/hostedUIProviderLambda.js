const response = require('cfn-response');
const aws = require('aws-sdk');

const identity = new aws.CognitoIdentityServiceProvider();
const cloudformation = new aws.CloudFormation();

exports.handler = (event, context) => {
  // Don't return promise, response.send() marks context as done internally
  const ignoredPromise = handleEvent(event, context);
};

async function handleEvent(event, context) {
  try {
    const userPoolId = event.ResourceProperties.userPoolId;
    const hostedUIProviderMeta = JSON.parse(event.ResourceProperties.hostedUIProviderMeta);
    const hostedUIProviderCreds = JSON.parse(event.ResourceProperties.hostedUIProviderCreds);
    const stackName = event.ResourceProperties.stackName;

    for (const providerMeta of hostedUIProviderMeta) {
      const providerCreds = hostedUIProviderCreds.find(({ ProviderName }) => providerMeta.ProviderName === ProviderName);
      if (providerMeta.ProviderName === 'SignInWithApple' && event.RequestType === 'Update') {
        const params = {
          UserPoolId: userPoolId,
          ProviderName: providerMeta.ProviderName,
          AttributeMapping: providerMeta.AttributeMapping,
        };

        if (providerCreds && providerCreds.client_id && providerCreds.team_id && providerCreds.key_id && providerCreds.private_key) {
          params.ProviderDetails = {
            client_id: providerCreds.client_id,
            team_id: providerCreds.team_id,
            key_id: providerCreds.key_id,
            private_key: providerCreds.private_key,
            authorize_scopes: providerMeta.authorize_scopes,
          };
        }

        await identity.updateIdentityProvider(params).promise();
      } else {
        try {
          if (stackName) {
            const { StackResources } = await cloudformation.describeStackResources({ StackName: stackName }).promise();
            const resource = StackResources.find(
              (resource) => resource.LogicalResourceId === `HostedUI${providerMeta.ProviderName}ProviderResource`,
            );
            const params = { ProviderName: providerMeta.ProviderName, UserPoolId: userPoolId };

            if (!resource) {
              await identity.deleteIdentityProvider(params).promise();
            }
          }
        } catch (err) {
          if (err?.code === 'NotFoundException' || err?.code === 'InvalidParameterException') {
            console.log('Not Found', providerMeta.ProviderName);
          } else {
            console.log(err);
            // bubble up to outer catch.
            throw err;
          }
        }
      }
    }

    response.send(event, context, response.SUCCESS);
  } catch (err) {
    console.log(err?.stack);
    response.send(event, context, response.FAILED, { err });
  }
}
