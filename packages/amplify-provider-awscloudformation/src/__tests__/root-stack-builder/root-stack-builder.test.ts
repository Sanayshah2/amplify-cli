import * as cdk from 'aws-cdk-lib';
import { AmplifyRootStack } from '../../root-stack-builder/root-stack-builder';
import { RootStackSynthesizer } from '../../root-stack-builder/stack-synthesizer';

describe('Check RootStack Template', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  test('root stack template generated by constructor', () => {
    const app = new cdk.App();
    const mockSynth = new RootStackSynthesizer();
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const stack = new AmplifyRootStack(app, 'rootStack', { synthesizer: mockSynth });
    app.synth();
    const templates = mockSynth.collectStacks();
    const cfnRootStack = templates.get('rootStack');
    expect(cfnRootStack).toMatchSnapshot();
  });

  test('root stack template generated by constructor with some parameters', () => {
    const app = new cdk.App();
    const mockSynth = new RootStackSynthesizer();
    const stack = new AmplifyRootStack(app, 'rootStack', { synthesizer: mockSynth });

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'DeploymentBucket',
      },
      'DeploymentBucketName',
    );

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'AuthRoleName',
      },
      'AuthRoleName',
    );

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'UnAuthRoleName',
      },
      'UnauthRoleName',
    );
    app.synth();
    const templates = mockSynth.collectStacks();
    const cfnRootStack = templates.get('rootStack');
    expect(cfnRootStack).toMatchSnapshot();
  });

  test('adding same logicalId parameter should throw error', () => {
    const app = new cdk.App();
    const mockSynth = new RootStackSynthesizer();
    const stack = new AmplifyRootStack(app, 'rootStack', { synthesizer: mockSynth });

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'AuthRoleName',
      },
      'AuthRoleName',
    );

    expect(() =>
      stack.addCfnParameter(
        {
          type: 'String',
          description: 'Name of the common deployment bucket provided by the parent stack',
          default: 'AuthRoleName',
        },
        'AuthRoleName',
      ),
    ).toThrow('Logical Id already exists: AuthRoleName.');
  });

  test('adding two resources with same logicalId throw error', () => {
    const app = new cdk.App();
    const mockSynth = new RootStackSynthesizer();
    const stack = new AmplifyRootStack(app, 'rootStack', { synthesizer: mockSynth });

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'DeploymentBucket',
      },
      'DeploymentBucketName',
    );

    // Add Outputs
    stack.addCfnOutput(
      {
        description: 'CloudFormation provider root stack Region',
        value: cdk.Fn.ref('AWS::Region'),
        exportName: cdk.Fn.sub('${AWS::StackName}-Region'),
      },
      'Region',
    );

    stack.addCfnOutput(
      {
        description: 'CloudFormation provider root stack ID',
        value: cdk.Fn.ref('AWS::StackName'),
        exportName: cdk.Fn.sub('${AWS::StackName}-StackName'),
      },
      'StackName',
    );

    expect(() =>
      stack.addCfnOutput(
        {
          description: 'CloudFormation provider root stack deployment bucket name',
          value: cdk.Fn.ref('DeploymentBucketName'),
          exportName: cdk.Fn.sub('${AWS::StackName}-DeploymentBucketName'),
        },
        'DeploymentBucketName',
      ),
    ).toThrow(`There is already a Construct with name 'DeploymentBucketName' in AmplifyRootStack`);
  });

  test('generates root stack Template', async () => {
    const app = new cdk.App();
    const mockSynth = new RootStackSynthesizer();
    const stack = new AmplifyRootStack(app, 'rootStack', { synthesizer: mockSynth });

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'DeploymentBucket',
      },
      'DeploymentBucketName',
    );

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'AuthRoleName',
      },
      'AuthRoleName',
    );

    stack.addCfnParameter(
      {
        type: 'String',
        description: 'Name of the common deployment bucket provided by the parent stack',
        default: 'UnAuthRoleName',
      },
      'UnauthRoleName',
    );

    // Add Outputs
    stack.addCfnOutput(
      {
        description: 'CloudFormation provider root stack Region',
        value: cdk.Fn.ref('AWS::Region'),
        exportName: cdk.Fn.sub('${AWS::StackName}-Region'),
      },
      'Region',
    );

    stack.addCfnOutput(
      {
        description: 'CloudFormation provider root stack ID',
        value: cdk.Fn.ref('AWS::StackName'),
        exportName: cdk.Fn.sub('${AWS::StackName}-StackName'),
      },
      'StackName',
    );

    stack.addCfnOutput(
      {
        description: 'CloudFormation provider root stack name',
        value: cdk.Fn.ref('AWS::StackId'),
        exportName: cdk.Fn.sub('${AWS::StackName}-StackId'),
      },
      'StackId',
    );

    stack.addCfnOutput(
      {
        value: cdk.Fn.getAtt('AuthRole', 'Arn').toString(),
      },
      'AuthRoleArn',
    );

    stack.addCfnOutput(
      {
        value: cdk.Fn.getAtt('UnauthRole', 'Arn').toString(),
      },
      'UnauthRoleArn',
    );

    await stack.generateRootStackResources();
    app.synth();
    const templates = mockSynth.collectStacks();
    const cfnRootStack = templates.get('rootStack');
    expect(cfnRootStack).toMatchSnapshot();
  });
});
