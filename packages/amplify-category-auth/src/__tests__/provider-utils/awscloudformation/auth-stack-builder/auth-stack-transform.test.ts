import { $TSContext } from '@aws-amplify/amplify-cli-core';
import process from 'process';
import { AmplifyAuthTransform } from '../../../../provider-utils/awscloudformation/auth-stack-builder';
import path from 'path';

jest.mock('@aws-amplify/amplify-cli-core', () => ({
  ...(jest.requireActual('@aws-amplify/amplify-cli-core') as {}),
  stateManager: {
    getLocalEnvInfo: jest.fn().mockReturnValue('testenv'),
    getMeta: jest.fn().mockReturnValue({
      auth: {
        resource1: {},
      },
    }),
  },
  pathManager: {
    getBackendDirPath: jest.fn().mockReturnValue(__dirname),
    getResourceCfnTemplatePath: jest.fn().mockImplementation(() => {
      return path.join(
        __dirname,
        'amplify',
        'backend',
        'auth',
        'extauth387063394_userpool_87063394',
        'build',
        'extauth387063394_userpool_87063394-cloudformation-template.json',
      );
    }),
    findProjectRoot: jest.fn().mockReturnValue(''),
    getCurrentCfnTemplatePathFromBuild: jest.fn().mockImplementation((categoryName, resourceName) => {
      return path.join(
        __dirname,
        'amplify',
        '#current-cloud-backend',
        categoryName,
        resourceName,
        `${resourceName}-cloudformation-template.json`,
      );
    })
  },
  JSONUtilities: {
    writeJson: jest.fn(),
    readJson: jest.fn(),
    stringify: jest.fn().mockImplementation(JSON.stringify),
    parse: jest.fn().mockImplementation(JSON.parse),
  },
  FeatureFlags: {
    getBoolean: jest.fn().mockReturnValue(true),
  },
  buildOverrideDir: jest.fn().mockResolvedValue(false),
  writeCFNTemplate: jest.fn().mockImplementation(() => Promise.resolve()),
}));

const inputPayload1 = {
  cognitoConfig: {
    identityPoolName: 'extauth387063394_identitypool_87063394',
    allowUnauthenticatedIdentities: true,
    resourceNameTruncated: 'extaut87063394',
    userPoolName: 'extauth387063394_userpool_87063394',
    autoVerifiedAttributes: ['email'],
    mfaConfiguration: 'ON',
    mfaTypes: ['SMS Text Message', 'TOTP'],
    smsAuthenticationMessage: 'Your authentication code is {####}',
    smsVerificationMessage: 'Your verification code is {####}',
    emailVerificationSubject: 'Your verification code',
    emailVerificationMessage: 'Your verification code is {####}',
    defaultPasswordPolicy: true,
    passwordPolicyMinLength: 8,
    passwordPolicyCharacters: ['Requires Lowercase', 'Requires Uppercase', 'Requires Numbers', 'Requires Symbols'],
    requiredAttributes: [
      'address',
      'birthdate',
      'email',
      'family_name',
      'middle_name',
      'gender',
      'locale',
      'given_name',
      'name',
      'nickname',
      'phone_number',
      'preferred_username',
      'picture',
      'profile',
      'updated_at',
      'website',
      'zoneinfo',
    ],
    userpoolClientGenerateSecret: false,
    userpoolClientRefreshTokenValidity: 30,
    userpoolClientWriteAttributes: ['address', 'email'],
    userpoolClientReadAttributes: ['address', 'email'],
    userpoolClientLambdaRole: 'extaut87063394_userpoolclient_lambda_role',
    userpoolClientSetAttributes: true,
    sharedId: '87063394',
    resourceName: 'extauth38706339487063394',
    authSelections: 'identityPoolAndUserPool',
    authRoleArn: {
      'Fn::GetAtt': ['AuthRole', 'Arn'],
    },
    unauthRoleArn: {
      'Fn::GetAtt': ['UnauthRole', 'Arn'],
    },
    useDefault: 'manual',
    thirdPartyAuth: true,
    authProviders: ['graph.facebook.com', 'accounts.google.com', 'www.amazon.com', 'appleid.apple.com'],
    facebookAppId: 'dfvsdcsdc',
    googleClientId: 'svsdvsv',
    amazonAppId: 'sdsafggas',
    appleAppId: 'gfdbvafergew',
    userPoolGroups: true,
    adminQueries: false,
    triggers: {
      CreateAuthChallenge: ['captcha-create-challenge'],
      CustomMessage: ['verification-link'],
      DefineAuthChallenge: ['captcha-define-challenge'],
      PostAuthentication: ['custom'],
      PostConfirmation: ['add-to-group'],
      PreAuthentication: ['custom'],
      PreSignup: ['email-filter-allowlist'],
      VerifyAuthChallengeResponse: ['captcha-verify'],
      PreTokenGeneration: ['alter-claims'],
    },
    hostedUI: true,
    hostedUIDomainName: 'extauth387063394-87063394',
    newCallbackURLs: ['https://localhost:3000/'],
    newLogoutURLs: ['https://localhost:3000/'],
    AllowedOAuthFlows: 'code',
    AllowedOAuthScopes: ['phone', 'email', 'openid', 'profile', 'aws.cognito.signin.user.admin'],
    authProvidersUserPool: ['Facebook', 'Google', 'LoginWithAmazon', 'SignInWithApple'],
    selectedParties:
      '{"graph.facebook.com":"dfvsdcsdc","accounts.google.com":"svsdvsv","www.amazon.com":"sdsafggas","appleid.apple.com":"gfdbvafergew"}',
    hostedUIProviderMeta:
      '[{"ProviderName":"Facebook","authorize_scopes":"email,public_profile","AttributeMapping":{"email":"email","username":"id"}},{"ProviderName":"Google","authorize_scopes":"openid email profile","AttributeMapping":{"email":"email","username":"sub"}},{"ProviderName":"LoginWithAmazon","authorize_scopes":"profile profile:user_id","AttributeMapping":{"email":"email","username":"user_id"}},{"ProviderName":"SignInWithApple","authorize_scopes":"email","AttributeMapping":{"email":"email"}}]',
    hostedUIProviderCreds:
      '[{"ProviderName":"Facebook","client_id":"sdcsdc","client_secret":"bfdsvsr"},{"ProviderName":"Google","client_id":"avearver","client_secret":"vcvereger"},{"ProviderName":"LoginWithAmazon","client_id":"vercvdsavcer","client_secret":"revfdsavrtv"},{"ProviderName":"SignInWithApple","client_id":"vfdvergver","team_id":"ervervre","key_id":"vfdavervfer","private_key":"vaveb"}]',
    oAuthMetadata:
      '{"AllowedOAuthFlows":["code"],"AllowedOAuthScopes":["phone","email","openid","profile","aws.cognito.signin.user.admin"],"CallbackURLs":["https://localhost:3000/"],"LogoutURLs":["https://localhost:3000/"]}',
    serviceName: 'Cognito',
    verificationBucketName: 'extauth38706339487063394verificationbucket',
    usernameCaseSensitive: false,
  },
};

const inputPayload2 = {
  version: '1',
  cognitoConfig: {
    identityPoolName: 'authdefaultsettings2c33facd_identitypool_2c33facd',
    allowUnauthenticatedIdentities: false,
    resourceNameTruncated: 'authde2c33facd',
    userPoolName: 'authdefaultsettings2c33facd_userpool_2c33facd',
    autoVerifiedAttributes: ['email'],
    mfaConfiguration: 'OFF',
    mfaTypes: ['SMS Text Message'],
    smsAuthenticationMessage: 'Your authentication code is {####}',
    smsVerificationMessage: 'Your verification code is {####}',
    emailVerificationSubject: 'Your verification code',
    emailVerificationMessage: 'Your verification code is {####}',
    defaultPasswordPolicy: false,
    passwordPolicyMinLength: 8,
    passwordPolicyCharacters: [],
    requiredAttributes: ['email'],
    aliasAttributes: ['email'],
    userpoolClientGenerateSecret: false,
    userpoolClientRefreshTokenValidity: 30,
    userpoolClientWriteAttributes: ['email'],
    userpoolClientReadAttributes: ['email'],
    userpoolClientLambdaRole: 'authde2c33facd_userpoolclient_lambda_role',
    userpoolClientSetAttributes: false,
    sharedId: '2c33facd',
    resourceName: 'authdefaultsettings2c33facd',
    authSelections: 'identityPoolAndUserPool',
    useDefault: 'default',
    userPoolGroupList: [],
    serviceName: 'Cognito',
    usernameCaseSensitive: false,
  },
};

const getCLIInputPayload_mock = jest.fn().mockReturnValueOnce(inputPayload1).mockReturnValueOnce(inputPayload2);

const isCLIInputsValid_mock = jest.fn().mockReturnValue('true');

jest.mock('../../../../provider-utils/awscloudformation/auth-inputs-manager/auth-input-state.ts', () => ({
  AuthInputState: jest.fn().mockImplementation(() => ({
    getCLIInputPayload: getCLIInputPayload_mock,
    isCLIInputsValid: isCLIInputsValid_mock,
  })),
}));

const mockPolicy1 = {
  policyName: 'AddToGroupCognito',
  trigger: 'PostConfirmation',
  effect: 'Allow',
  actions: ['cognito-idp:AdminAddUserToGroup', 'cognito-idp:GetGroup', 'cognito-idp:CreateGroup'],
  resource: {
    paramType: '!GetAtt',
    keys: ['UserPool', 'Arn'],
  },
};

const context_stub = {
  amplify: {
    loadEnvResourceParameters: jest.fn(),
    getTriggerPermissions: jest.fn().mockImplementation(() => [JSON.stringify(mockPolicy1)]),
    dependsOnBlock: jest.fn(),
    updateamplifyMetaAfterResourceAdd: jest.fn(),
  },
  print: {
    error: jest.fn(),
  },
};

const context_stub_typed = context_stub as unknown as $TSContext;
describe('Check Auth Template', () => {
  it('Generated authstack template in manual flow', async () => {
    // CFN transform for Auth stack

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);
    expect(mock_template).toMatchSnapshot();
  });

  it('Generated authstack template in default flow', async () => {
    // CFN transform for Auth stack

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);
    expect(mock_template).toMatchSnapshot();
  });

  it('should include username case sensitivity when the aliasAttribute contains prefer_username', async () => {
    getCLIInputPayload_mock.mockReset();
    getCLIInputPayload_mock.mockReturnValue({
      cognitoConfig: {
        ...inputPayload1.cognitoConfig,
        aliasAttributes: ['preferred_username', 'email'],
      },
    });

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);
    expect(mock_template.Resources?.UserPool.Properties.UsernameConfiguration).toEqual({ CaseSensitive: false });

    getCLIInputPayload_mock.mockReturnValue({
      cognitoConfig: {
        ...inputPayload1.cognitoConfig,
        aliasAttributes: ['email'],
      },
    });

    const authTransform2 = new AmplifyAuthTransform(resourceName);
    const mock_template2 = await authTransform2.transform(context_stub_typed);
    expect(mock_template2.Resources?.UserPool.Properties).not.toContain('UsernameConfiguration');
  });

  it('should validate cfn parameters if no original', () => {
    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const isValid = authTransform.validateCfnParameters(context_stub_typed, false, { requiredAttributes: ['email'] });
    expect(isValid).toBe(true);
  });

  it('should validate cfn parameters if match', () => {
    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const isValid = authTransform.validateCfnParameters(
      context_stub_typed,
      { requiredAttributes: ['email'] },
      { requiredAttributes: ['email'] },
    );
    expect(isValid).toBe(true);
  });

  it('should not validate cfn parameters if no match', () => {
    // @ts-ignore
    process.exit = jest.fn();
    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    authTransform.validateCfnParameters(
      context_stub_typed,
      { requiredAttributes: ['email'] },
      { requiredAttributes: ['email', 'phone_number'] },
    );
    expect(process.exit).toBeCalledTimes(1);
  });

  it('should include oauth settings in cfn when enabled oauth', async () => {
    getCLIInputPayload_mock.mockReset();
    getCLIInputPayload_mock.mockReturnValue({
      cognitoConfig: {
        ...inputPayload1.cognitoConfig,
        oAuthMetadata:
          '{"AllowedOAuthFlows":["code"],"AllowedOAuthScopes":["phone","email","openid","profile","aws.cognito.signin.user.admin"],"CallbackURLs":["https://localhost:3000/"]}',
      },
    });

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);
    expect(mock_template.Resources?.UserPoolClient.Properties.AllowedOAuthFlows).toMatchInlineSnapshot(`
      Array [
        "code",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClient.Properties.AllowedOAuthScopes).toMatchInlineSnapshot(`
      Array [
        "phone",
        "email",
        "openid",
        "profile",
        "aws.cognito.signin.user.admin",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClient.Properties.CallbackURLs).toMatchInlineSnapshot(`
      Array [
        "https://localhost:3000/",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClient.Properties.LogoutURLs).toMatchInlineSnapshot(`undefined`);

    expect(mock_template.Resources?.UserPoolClientWeb.Properties.AllowedOAuthFlows).toMatchInlineSnapshot(`
      Array [
        "code",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClientWeb.Properties.AllowedOAuthScopes).toMatchInlineSnapshot(`
      Array [
        "phone",
        "email",
        "openid",
        "profile",
        "aws.cognito.signin.user.admin",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClientWeb.Properties.CallbackURLs).toMatchInlineSnapshot(`
      Array [
        "https://localhost:3000/",
      ]
    `);
    expect(mock_template.Resources?.UserPoolClientWeb.Properties.LogoutURLs).toMatchInlineSnapshot(`undefined`);
  });

  it('includes social sign in "Parameters" with no echo params', async () => {
    getCLIInputPayload_mock.mockReset();
    getCLIInputPayload_mock.mockReturnValue({
      cognitoConfig: {
        ...inputPayload1.cognitoConfig,
        oAuthMetadata:
          '{"AllowedOAuthFlows":["code"],"AllowedOAuthScopes":["phone","email","openid","profile","aws.cognito.signin.user.admin"],"CallbackURLs":["https://localhost:3000/"]}',
      },
    });

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);

    expect(mock_template.Parameters!.facebookAppIdUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
    expect(mock_template.Parameters!.facebookAppSecretUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );

    expect(mock_template.Parameters!.googleAppIdUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
    expect(mock_template.Parameters!.googleAppSecretUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );

    expect(mock_template.Parameters!.loginwithamazonAppIdUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
    expect(mock_template.Parameters!.loginwithamazonAppSecretUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );

    expect(mock_template.Parameters!.signinwithappleClientIdUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
    expect(mock_template.Parameters!.signinwithappleKeyIdUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
    expect(mock_template.Parameters!.signinwithapplePrivateKeyUserPool).toMatchInlineSnapshot(
      {
        Type: 'String',
        NoEcho: true,
      },
      `
      Object {
        "NoEcho": true,
        "Type": "String",
      }
    `,
    );
  });

  it('includes social sign in "Resources"', async () => {
    getCLIInputPayload_mock.mockReset();
    getCLIInputPayload_mock.mockReturnValue({
      cognitoConfig: {
        ...inputPayload1.cognitoConfig,
        oAuthMetadata:
          '{"AllowedOAuthFlows":["code"],"AllowedOAuthScopes":["phone","email","openid","profile","aws.cognito.signin.user.admin"],"CallbackURLs":["https://localhost:3000/"]}',
      },
    });

    const resourceName = 'mockResource';
    const authTransform = new AmplifyAuthTransform(resourceName);
    const mock_template = await authTransform.transform(context_stub_typed);

    expect(mock_template.Resources!.HostedUIFacebookProviderResource.Properties.AttributeMapping).toMatchInlineSnapshot(
      { email: 'email', username: 'id' },
      `
      Object {
        "email": "email",
        "username": "id",
      }
    `,
    );
    expect(mock_template.Resources!.HostedUIFacebookProviderResource.Properties.ProviderDetails).toMatchInlineSnapshot(
      {
        authorize_scopes: { Ref: 'facebookAuthorizeScopes' },
        client_id: { Ref: 'facebookAppIdUserPool' },
        client_secret: { Ref: 'facebookAppSecretUserPool' },
      },
      `
      Object {
        "authorize_scopes": Object {
          "Ref": "facebookAuthorizeScopes",
        },
        "client_id": Object {
          "Ref": "facebookAppIdUserPool",
        },
        "client_secret": Object {
          "Ref": "facebookAppSecretUserPool",
        },
      }
    `,
    );

    expect(mock_template.Resources!.HostedUIGoogleProviderResource.Properties.AttributeMapping).toMatchInlineSnapshot(
      { email: 'email', username: 'sub' },
      `
      Object {
        "email": "email",
        "username": "sub",
      }
    `,
    );
    expect(mock_template.Resources!.HostedUIGoogleProviderResource.Properties.ProviderDetails).toMatchInlineSnapshot(
      {
        authorize_scopes: { Ref: 'googleAuthorizeScopes' },
        client_id: { Ref: 'googleAppIdUserPool' },
        client_secret: { Ref: 'googleAppSecretUserPool' },
      },
      `
      Object {
        "authorize_scopes": Object {
          "Ref": "googleAuthorizeScopes",
        },
        "client_id": Object {
          "Ref": "googleAppIdUserPool",
        },
        "client_secret": Object {
          "Ref": "googleAppSecretUserPool",
        },
      }
    `,
    );

    expect(mock_template.Resources!.HostedUILoginWithAmazonProviderResource.Properties.AttributeMapping).toMatchInlineSnapshot(
      { email: 'email', username: 'user_id' },
      `
      Object {
        "email": "email",
        "username": "user_id",
      }
    `,
    );
    expect(mock_template.Resources!.HostedUILoginWithAmazonProviderResource.Properties.ProviderDetails).toMatchInlineSnapshot(
      {
        authorize_scopes: { Ref: 'loginwithamazonAuthorizeScopes' },
        client_id: { Ref: 'loginwithamazonAppIdUserPool' },
        client_secret: { Ref: 'loginwithamazonAppSecretUserPool' },
      },
      `
      Object {
        "authorize_scopes": Object {
          "Ref": "loginwithamazonAuthorizeScopes",
        },
        "client_id": Object {
          "Ref": "loginwithamazonAppIdUserPool",
        },
        "client_secret": Object {
          "Ref": "loginwithamazonAppSecretUserPool",
        },
      }
    `,
    );

    expect(mock_template.Resources!.HostedUISignInWithAppleProviderResource.Properties.AttributeMapping).toMatchInlineSnapshot(
      { email: 'email' },
      `
      Object {
        "email": "email",
      }
    `,
    );
    expect(mock_template.Resources!.HostedUISignInWithAppleProviderResource.Properties.ProviderDetails).toMatchInlineSnapshot(
      {
        authorize_scopes: { Ref: 'signinwithappleAuthorizeScopes' },
        client_id: { Ref: 'signinwithappleClientIdUserPool' },
        key_id: { Ref: 'signinwithappleKeyIdUserPool' },
        private_key: { Ref: 'signinwithapplePrivateKeyUserPool' },
        team_id: { Ref: 'signinwithappleTeamIdUserPool' },
      },
      `
      Object {
        "authorize_scopes": Object {
          "Ref": "signinwithappleAuthorizeScopes",
        },
        "client_id": Object {
          "Ref": "signinwithappleClientIdUserPool",
        },
        "key_id": Object {
          "Ref": "signinwithappleKeyIdUserPool",
        },
        "private_key": Object {
          "Ref": "signinwithapplePrivateKeyUserPool",
        },
        "team_id": Object {
          "Ref": "signinwithappleTeamIdUserPool",
        },
      }
    `,
    );
  });
});
