#!/usr/bin/env node
import path from 'node:path';

import { Gen2RenderingOptions, createGen2Renderer } from '@aws-amplify/amplify-gen2-codegen';

import { AmplifyClient } from '@aws-sdk/client-amplify';
import { CloudFormationClient } from '@aws-sdk/client-cloudformation';
import { CognitoIdentityProviderClient, LambdaConfigType } from '@aws-sdk/client-cognito-identity-provider';
import { CognitoIdentityClient } from '@aws-sdk/client-cognito-identity';
import { S3Client } from '@aws-sdk/client-s3';
import { LambdaClient } from '@aws-sdk/client-lambda';
import { BackendDownloader } from './backend_downloader';
import { AppContextLogger } from './logger';
import { BackendEnvironmentResolver } from './backend_environment_selector';
import { Analytics, AppAnalytics } from './analytics';
import { AppAuthDefinitionFetcher } from './app_auth_definition_fetcher';
import { AppStorageDefinitionFetcher } from './app_storage_definition_fetcher';
import { AmplifyCategories, stateManager } from '@aws-amplify/amplify-cli-core';
import { AuthTriggerConnection } from '@aws-amplify/amplify-gen1-codegen-auth-adapter';
import { DataDefinitionFetcher } from './data_definition_fetcher';
import { AmplifyStackParser } from './amplify_stack_parser';
import { AppFunctionsDefinitionFetcher } from './app_functions_definition_fetcher';

interface CodegenCommandParameters {
  analytics: Analytics;
  logger: AppContextLogger;
  outputDirectory: string;
  backendEnvironmentName: string | undefined;
  appId: string;
  dataDefinitionFetcher: DataDefinitionFetcher;
  authDefinitionFetcher: AppAuthDefinitionFetcher;
  storageDefinitionFetcher: AppStorageDefinitionFetcher;
  functionsDefinitionFetcher: AppFunctionsDefinitionFetcher;
}

export type AuthCliInputs = Record<string, unknown>;

const generateGen2Code = async ({
  logger,
  analytics,
  outputDirectory,
  backendEnvironmentName,
  appId,
  authDefinitionFetcher,
  dataDefinitionFetcher,
  storageDefinitionFetcher,
  functionsDefinitionFetcher,
}: CodegenCommandParameters) => {
  logger.log(`Getting info for Amplify app`);

  logger.log('Getting latest environment info');

  const gen2RenderOptions: Readonly<Gen2RenderingOptions> = {
    outputDir: outputDirectory,
    appId: appId,
    backendEnvironmentName: backendEnvironmentName,
    auth: await authDefinitionFetcher.getDefinition(),
    storage: await storageDefinitionFetcher.getDefinition(),
    data: await dataDefinitionFetcher.getDefinition(),
    functions: await functionsDefinitionFetcher.getDefinition(),
    unsupportedCategories: unsupportedCategories(),
  };

  const pipeline = createGen2Renderer(gen2RenderOptions);
  try {
    await pipeline.render();
    await analytics.logEvent('finishedMigration');
  } catch (e) {
    await analytics.logEvent('failedMigration');
  }
};

type AmplifyMetaAuth = {
  service: 'Cognito';
  providerPlugin: 'awscloudformation';
};

type AmplifyMeta = {
  auth: Record<string, AmplifyMetaAuth>;
};

const getFunctionPath = (functionName: string) => {
  return path.join('amplify', 'backend', 'function', functionName, 'src');
};

const getAuthTriggersConnections = async (): Promise<Partial<Record<keyof LambdaConfigType, string>>> => {
  const amplifyMeta: AmplifyMeta = stateManager.getMeta();
  const resourceName = Object.keys(amplifyMeta.auth)[0];
  const authInputs = stateManager.getResourceInputsJson(undefined, AmplifyCategories.AUTH, resourceName);
  if ('cognitoConfig' in authInputs && 'authTriggerConnections' in authInputs.cognitoConfig) {
    try {
      let triggerConnections: AuthTriggerConnection[];
      // Check if authTriggerConnections is a valid JSON string
      if (typeof authInputs.cognitoConfig.authTriggerConnections === 'string') {
        triggerConnections = JSON.parse(authInputs.cognitoConfig.authTriggerConnections);
      } else {
        // If not a valid JSON string, assume it's an array of JSON strings
        triggerConnections = authInputs.cognitoConfig.authTriggerConnections.map((connection: string) => JSON.parse(connection));
      }
      const connections = triggerConnections.reduce((prev, curr) => {
        prev[curr.triggerType] = getFunctionPath(curr.lambdaFunctionName);
        return prev;
      }, {} as Partial<Record<keyof LambdaConfigType, string>>);
      return connections;
    } catch (e) {
      console.log('error -- ', e);
      throw new Error('Error parsing auth trigger connections');
    }
  }
  return {};
};

const resolveAppId = (): string => {
  const meta = stateManager.getMeta();
  return meta?.providers?.awscloudformation?.AmplifyAppId;
};

const unsupportedCategories = (): Map<string, string> => {
  const unsupportedCategories = new Map<string, string>();

  unsupportedCategories.set('geo', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/geo/');
  unsupportedCategories.set('analytics', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/analytics/');
  unsupportedCategories.set('predictions', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/predictions/');
  unsupportedCategories.set('notifications', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/in-app-messaging/');
  unsupportedCategories.set('interactions', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/interactions/');
  unsupportedCategories.set('custom', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/custom-resources/');
  unsupportedCategories.set('api', 'https://docs.amplify.aws/react/build-a-backend/add-aws-services/rest-api/');

  const meta = stateManager.getMeta();
  const categories = Object.keys(meta);

  const unsupportedCategoriesList = new Map<string, string>();

  categories.forEach((category) => {
    if (category == 'api') {
      const apiList = meta?.api;
      if (apiList) {
        Object.keys(apiList).forEach((api) => {
          const apiObj = apiList[api];
          if (apiObj.service == 'API Gateway') {
            unsupportedCategoriesList.set(category, unsupportedCategories.get(category)!);
          }
        });
      }
    } else {
      if (unsupportedCategories.has(category)) {
        unsupportedCategoriesList.set(category, unsupportedCategories.get(category)!);
      }
    }
  });

  return unsupportedCategoriesList;
};

export async function execute() {
  const amplifyClient = new AmplifyClient();
  const s3Client = new S3Client();
  const cloudFormationClient = new CloudFormationClient();
  const cognitoIdentityProviderClient = new CognitoIdentityProviderClient();
  const cognitoIdentityPoolClient = new CognitoIdentityClient();
  const lambdaClient = new LambdaClient({
    region: stateManager.getCurrentRegion(),
  });
  const appId = resolveAppId();

  const amplifyStackParser = new AmplifyStackParser(cloudFormationClient);
  const backendEnvironmentResolver = new BackendEnvironmentResolver(appId, amplifyClient);
  const backendEnvironment = await backendEnvironmentResolver.selectBackendEnvironment();

  await generateGen2Code({
    outputDirectory: './output',
    storageDefinitionFetcher: new AppStorageDefinitionFetcher(backendEnvironmentResolver, new BackendDownloader(s3Client), s3Client),
    authDefinitionFetcher: new AppAuthDefinitionFetcher(
      cognitoIdentityPoolClient,
      cognitoIdentityProviderClient,
      amplifyStackParser,
      backendEnvironmentResolver,
      () => getAuthTriggersConnections(),
    ),
    dataDefinitionFetcher: new DataDefinitionFetcher(backendEnvironmentResolver, amplifyStackParser),
    functionsDefinitionFetcher: new AppFunctionsDefinitionFetcher(lambdaClient, backendEnvironmentResolver, stateManager),
    analytics: new AppAnalytics(appId),
    logger: new AppContextLogger(appId),
    backendEnvironmentName: backendEnvironment?.environmentName,
    appId: appId,
  });
}
