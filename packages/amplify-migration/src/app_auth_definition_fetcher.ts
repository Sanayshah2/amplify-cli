import assert from 'node:assert';
import { AuthDefinition } from '@aws-amplify/amplify-gen2-codegen';
export type AuthTriggerConnectionsFetcher = () => Promise<Partial<Record<keyof LambdaConfigType, string>> | undefined>;
import { AmplifyStackParser } from './amplify_stack_parser';
import { BackendEnvironmentResolver } from './backend_environment_selector';
import {
  CognitoIdentityProviderClient,
  DescribeUserPoolCommand,
  DescribeUserPoolClientCommand,
  ListIdentityProvidersCommand,
  LambdaConfigType,
  ListGroupsCommand,
  IdentityProviderType,
  DescribeIdentityProviderCommand,
  GetUserPoolMfaConfigCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoIdentityClient, DescribeIdentityPoolCommand, GetIdentityPoolRolesCommand } from '@aws-sdk/client-cognito-identity';
import { BackendDownloader } from './backend_downloader.js';
import { getAuthDefinition } from '@aws-amplify/amplify-gen1-codegen-auth-adapter';
import { fileOrDirectoryExists } from './directory_exists';
import path from 'node:path';
import * as fs from 'fs-extra';
import { ReferenceAuth } from '@aws-amplify/amplify-gen2-codegen/src/auth/source_builder';

export interface AppAuthDefinitionFetcher {
  getDefinition(): Promise<AuthDefinition | undefined>;
}

export class AppAuthDefinitionFetcher {
  constructor(
    private cognitoIdentityPoolClient: CognitoIdentityClient,
    private cognitoIdentityProviderClient: CognitoIdentityProviderClient,
    private stackParser: AmplifyStackParser,
    private backendEnvironmentResolver: BackendEnvironmentResolver,
    private ccbFetcher: BackendDownloader,
    private getAuthTriggerConnections: AuthTriggerConnectionsFetcher,
  ) {}

  private readJsonFile = async (filePath: string) => {
    const contents = await fs.readFileSync(filePath, { encoding: 'utf8' });
    return JSON.parse(contents);
  };

  private getUserPool = async (userPoolId: string | undefined) => {
    const { UserPool: userPool } = await this.cognitoIdentityProviderClient.send(
      new DescribeUserPoolCommand({
        UserPoolId: userPoolId,
      }),
    );
    return userPool;
  };

  private getReferenceAuth = async () => {
    const backendEnvironment = await this.backendEnvironmentResolver.selectBackendEnvironment();
    if (!backendEnvironment?.deploymentArtifacts) return undefined;
    const currentCloudBackendDirectory = await this.ccbFetcher.getCurrentCloudBackend(backendEnvironment.deploymentArtifacts);
    const amplifyMetaPath = path.join(currentCloudBackendDirectory, 'amplify-meta.json');

    if (!(await fileOrDirectoryExists(amplifyMetaPath))) {
      throw new Error('Could not find amplify-meta.json');
    }

    const amplifyMeta = (await this.readJsonFile(amplifyMetaPath)) ?? {};
    const isImported = Object.keys(amplifyMeta.auth).map((key) => amplifyMeta.auth[key])[0].serviceType === 'imported';

    if ('auth' in amplifyMeta && isImported) {
      const {
        UserPoolId: userPoolId,
        AppClientIDWeb: userPoolClientId,
        IdentityPoolId: identityPoolId,
      } = Object.keys(amplifyMeta.auth).map((key) => amplifyMeta.auth[key])[0].output;
      const { Roles } = await this.cognitoIdentityPoolClient.send(
        new GetIdentityPoolRolesCommand({
          IdentityPoolId: identityPoolId,
        }),
      );

      if (Roles) {
        const authRoleArn = Roles.authenticated;
        const unauthRoleArn = Roles.unauthenticated;
        const referenceAuth: ReferenceAuth = {
          userPoolId,
          userPoolClientId,
          identityPoolId,
          unauthRoleArn,
          authRoleArn,
        };
        return referenceAuth;
      }
    }
    return undefined;
  };

  getDefinition = async (): Promise<AuthDefinition | undefined> => {
    const referenceAuth = await this.getReferenceAuth();
    if (referenceAuth) {
      const userPool = await this.getUserPool(referenceAuth.userPoolId);
      assert(userPool, 'User pool not found');
      return getAuthDefinition({
        userPool,
        referenceAuth,
      });
    }
    const backendEnvironment = await this.backendEnvironmentResolver.selectBackendEnvironment();
    assert(backendEnvironment?.stackName);
    const stackResources = await this.stackParser.getAllStackResources(backendEnvironment.stackName);
    const resourcesByLogicalId = this.stackParser.getResourcesByLogicalId(stackResources);

    if (!resourcesByLogicalId['UserPool']) {
      return undefined;
    }

    const userPool = await this.getUserPool(resourcesByLogicalId['UserPool'].PhysicalResourceId);

    const { MfaConfiguration: mfaConfig, SoftwareTokenMfaConfiguration: totpConfig } = await this.cognitoIdentityProviderClient.send(
      new GetUserPoolMfaConfigCommand({
        UserPoolId: resourcesByLogicalId['UserPool'].PhysicalResourceId,
      }),
    );

    const { UserPoolClient: webClient } = await this.cognitoIdentityProviderClient.send(
      new DescribeUserPoolClientCommand({
        UserPoolId: resourcesByLogicalId['UserPool'].PhysicalResourceId,
        ClientId: resourcesByLogicalId['UserPoolClientWeb'].PhysicalResourceId,
      }),
    );

    const { Providers: identityProviders } = await this.cognitoIdentityProviderClient.send(
      new ListIdentityProvidersCommand({
        UserPoolId: resourcesByLogicalId['UserPool'].PhysicalResourceId,
      }),
    );

    const identityProvidersDetails: IdentityProviderType[] = [];
    for (const provider of identityProviders || []) {
      const { IdentityProvider: providerDetails } = await this.cognitoIdentityProviderClient.send(
        new DescribeIdentityProviderCommand({
          UserPoolId: resourcesByLogicalId['UserPool'].PhysicalResourceId,
          ProviderName: provider.ProviderName,
        }),
      );
      if (providerDetails) {
        identityProvidersDetails.push(providerDetails);
      }
    }

    const { Groups: identityGroups } = await this.cognitoIdentityProviderClient.send(
      new ListGroupsCommand({
        UserPoolId: resourcesByLogicalId['UserPool'].PhysicalResourceId,
      }),
    );

    const { AllowUnauthenticatedIdentities: guestLogin, IdentityPoolName: identityPoolName } = await this.cognitoIdentityPoolClient.send(
      new DescribeIdentityPoolCommand({
        IdentityPoolId: resourcesByLogicalId['IdentityPool'].PhysicalResourceId,
      }),
    );

    const authTriggerConnections = await this.getAuthTriggerConnections();

    assert(userPool, 'User pool not found');
    return getAuthDefinition({
      userPool,
      identityPoolName,
      identityProviders,
      identityProvidersDetails,
      identityGroups,
      webClient,
      authTriggerConnections,
      guestLogin,
      mfaConfig,
      totpConfig,
    });
  };
}
