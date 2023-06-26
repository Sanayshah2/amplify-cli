import { $TSAny, $TSContext, $TSObject, JSONUtilities, pathManager, Template } from '@aws-amplify/amplify-cli-core';
import { ICognitoUserPoolService } from '@aws-amplify/amplify-util-import';
import { generateUserPoolClient } from './generate-user-pool-client';
import { getUserPoolIdFromMeta } from './get-from-amplify-meta';
import { ProviderMeta } from '../auth-stack-builder/types';

const { readJson } = JSONUtilities;
const { getCurrentCfnTemplatePathFromBuild } = pathManager;

export const migrateResourcesToCfn = (resourceName: string, meta: ProviderMeta[]): boolean => {
  const authCfnTemplatePath = getCurrentCfnTemplatePathFromBuild('auth', resourceName);
  const authCfnTemplate: Template | undefined = readJson(authCfnTemplatePath, { throwIfNotExist: false });
  const lambdaCalloutCreatedInCloud = authCfnTemplate?.Resources?.HostedUIProvidersCustomResource?.Type === 'AWS::Lambda::Function';
  const providerCreatedInCloud = hasHostedProviderResources(authCfnTemplate);

  // Apple has been fully migrated to CFN-maintained resource
  const hasSignInWithApple = meta.find((provider: ProviderMeta) => provider.ProviderName === 'SignInWithApple');
  const cloudDoesNotHaveApple = !hasHostedSignInWithAppleProviderResource(authCfnTemplate);
  const appleNotCreatedWithCfn = !!hasSignInWithApple && cloudDoesNotHaveApple;

  return (lambdaCalloutCreatedInCloud && !providerCreatedInCloud) || appleNotCreatedWithCfn;
};

const hasHostedProviderResources = (authCfnTemplate: Template | undefined): boolean => {
  return (
    authCfnTemplate?.Resources?.HostedUIFacebookProviderResource?.Type === 'AWS::Cognito::UserPoolIdentityProvider' ||
    authCfnTemplate?.Resources?.HostedUIGoogleProviderResource?.Type === 'AWS::Cognito::UserPoolIdentityProvider' ||
    authCfnTemplate?.Resources?.HostedUILoginWithAmazonProviderResource?.Type === 'AWS::Cognito::UserPoolIdentityProvider' ||
    hasHostedSignInWithAppleProviderResource(authCfnTemplate)
  );
};

const hasHostedSignInWithAppleProviderResource = (authCfnTemplate: Template | undefined): boolean => {
  return authCfnTemplate?.Resources?.HostedUISignInWithAppleProviderResource?.Type === 'AWS::Cognito::UserPoolIdentityProvider';
};

/*
 * This function iterates over the user-inputted hostedUICreds and makes SDK calls
 * to populate non-user-updated creds in the array.
 */

export const getHostedUIProviderCredsFromCloud = async (
  resourceName: string,
  providerMeta: $TSObject[],
  updatedUIProviderCreds: $TSObject[],
  context?: $TSContext,
): Promise<$TSObject[]> => {
  const userPoolId = getUserPoolIdFromMeta(resourceName);
  const providerCredsArr = [];

  for (const provider of providerMeta) {
    const providerCreds = updatedUIProviderCreds?.find(({ ProviderName }) => ProviderName === provider.ProviderName) || {};
    const hasEmptyCreds = Object.keys(providerCreds).length === 0;
    const hasNotBeenUpdated = providerCreds && Object.keys(providerCreds).length === 1 && 'ProviderName' in providerCreds;
    let credsFromCloud;

    if ((hasNotBeenUpdated || hasEmptyCreds) && userPoolId && context) {
      const client = await generateUserPoolClient(context);

      try {
        credsFromCloud = await getProviderCreds(userPoolId, provider.ProviderName, client);
        credsFromCloud.ProviderName = provider.ProviderName;
      } catch (e) {
        // noop
      }
    }

    providerCredsArr.push(credsFromCloud || providerCreds);
  }

  return providerCredsArr;
};

export const getProviderCreds = async (userPoolId: string, providerName: string, client: ICognitoUserPoolService): Promise<$TSAny> => {
  return (await client.getUserPoolIdentityProviderDetails(userPoolId, providerName))?.IdentityProvider?.ProviderDetails;
};