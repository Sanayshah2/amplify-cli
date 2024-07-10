import { $TSContext } from '@aws-amplify/amplify-cli-core';
import { printer, prompter } from '@aws-amplify/amplify-prompts';
import { preInitSetup, preInitSetupBasic, gen2Recommendation } from '../../init-steps/preInitSetup';
import { isNewProject } from '../../init-steps/s0-analyzeProject';

// Mock dependencies
jest.mock('@aws-amplify/amplify-cli-core', () => ({
  ...(jest.requireActual('@aws-amplify/amplify-cli-core') as {}),
  FeatureFlags: {
    getBoolean: jest.fn(),
    getNumber: jest.fn(),
    isInitialized: jest.fn().mockReturnValue(true),
    ensureDefaultFeatureFlags: jest.fn(),
  },
  getPackageManager: jest.fn(),
}));

jest.mock('@aws-amplify/amplify-prompts', () => ({
  printer: {
    warn: jest.fn(),
  },
  prompter: {
    confirmContinue: jest.fn(),
    pick: jest.fn(),
  },
}));

jest.mock('../../init-steps/s0-analyzeProject', () => ({
  isNewProject: jest.fn(),
}));

describe('preInitSetup', () => {
  it('should return preInitSetupBasic when isHeadless is true', () => {
    const result = preInitSetup(true);
    expect(result).toBe(preInitSetupBasic);
  });

  it('should return a function when isHeadless is false', () => {
    const result = preInitSetup(false);
    expect(typeof result).toBe('function');
  });
});

describe('gen2Recommendation', () => {
  let context;

  beforeEach(() => {
    context = { exeInfo: {} } as $TSContext;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should recommend using Gen 2 for new projects', async () => {
    const isNewProjectMock = jest.mocked(isNewProject);
    isNewProjectMock.mockReturnValue(true);

    const confirmContinueMock = jest.mocked(require('@aws-amplify/amplify-prompts').prompter.confirmContinue);
    confirmContinueMock.mockResolvedValue(true);

    const pickMock = jest.mocked(require('@aws-amplify/amplify-prompts').prompter.pick);
    pickMock.mockResolvedValue('I am a current Gen 1 user');

    await gen2Recommendation(context);

    expect(require('@aws-amplify/amplify-prompts').printer.warn).toHaveBeenCalledWith(
      'AWS Amplify recommends using Amplify Gen 2 for new projects. Learn how to get started at https://docs.amplify.aws/react/start/quickstart/',
    );
    expect(confirmContinueMock).toHaveBeenCalledWith('Do you want to continue with Amplify Gen 1?');
    expect(pickMock).toHaveBeenCalledWith('Why would you like to use Amplify Gen 1?', expect.any(Array));
    expect(context.exeInfo.projectConfig).toEqual({ whyContinueWithGen1: 'I am a current Gen 1 user' });
  });

  it('should return the context for existing projects', async () => {
    const isNewProjectMock = jest.mocked(isNewProject);
    isNewProjectMock.mockReturnValue(false);

    const result = await gen2Recommendation(context);

    expect(result).toEqual(context);
    expect(printer.warn).not.toHaveBeenCalled();
    expect(prompter.confirmContinue).not.toHaveBeenCalled();
    expect(prompter.pick).not.toHaveBeenCalled();
  });
});