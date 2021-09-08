import {
  initJSProjectWithProfile,
  deleteProject,
  createNewProjectDir,
  deleteProjectDir,
  addApiWithSchema,
  amplifyPush,
  getProjectMeta,
} from 'amplify-e2e-core';
import { testSchema } from '../schema-api-directives';

describe('api directives @allow_public_data_access_with_api_key', () => {
  let projectDir: string;
  const envName = 'dev';

  beforeEach(async () => {
    projectDir = await createNewProjectDir('model');
    await initJSProjectWithProfile(projectDir, { envName });
  });

  afterEach(async () => {
    await deleteProject(projectDir);
    deleteProjectDir(projectDir);
  });

  it('schema and files generate with sandbox mode', async () => {
    await addApiWithSchema(projectDir, 'model_with_sandbox_mode.graphql');
    await amplifyPush(projectDir);

    const meta = getProjectMeta(projectDir);
    const { output } = meta.api.simplemodel;
    const { authConfig, globalSandboxModeConfig, GraphQLAPIIdOutput, GraphQLAPIEndpointOutput, GraphQLAPIKeyOutput } = output;

    expect(globalSandboxModeConfig[envName].enabled).toBe(true);
    expect(authConfig.defaultAuthentication.authenticationType).toBe('API_KEY');
    expect(authConfig.defaultAuthentication.apiKeyConfig.apiKeyExpirationDate).toBeDefined();

    expect(GraphQLAPIIdOutput).toBeDefined();
    expect(GraphQLAPIEndpointOutput).toBeDefined();
    expect(GraphQLAPIKeyOutput).toBeDefined();

    const testresult = await testSchema(projectDir, 'model', 'generates');
    expect(testresult).toBeTruthy();
  });
});
