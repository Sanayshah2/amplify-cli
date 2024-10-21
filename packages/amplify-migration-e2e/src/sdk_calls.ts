import { CloudControlClient, GetResourceCommand } from '@aws-sdk/client-cloudcontrol';
import { AppSyncClient, GetDataSourceCommand } from '@aws-sdk/client-appsync';
import { CognitoIdentityClient, DescribeIdentityPoolCommand } from '@aws-sdk/client-cognito-identity';

export async function getAppSyncDataSource(apiId: string, dataSourceName: string, region: string) {
  const client = new AppSyncClient({ region });
  const command = new GetDataSourceCommand({
    apiId: apiId,
    name: dataSourceName,
  });
  const response = await client.send(command);
  return response.dataSource;
}

export async function getResourceDetails(typeName: string, identifier: string, region: string) {
  const client = new CloudControlClient({ region });
  const command = new GetResourceCommand({
    TypeName: typeName,
    Identifier: identifier,
  });
  const response = await client.send(command);
  return JSON.parse(response.ResourceDescription.Properties);
}

export async function getIdentityPool(identityPoolId: string, region: string) {
  const client = new CognitoIdentityClient({ region });
  const command = new DescribeIdentityPoolCommand({
    IdentityPoolId: identityPoolId,
  });
  const response = await client.send(command);
  return response;
}