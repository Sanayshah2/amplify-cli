import { FunctionDefinition } from '@aws-amplify/amplify-gen2-codegen';
import { FunctionConfiguration } from '@aws-sdk/client-lambda';

export const getFunctionDefinition = (functionConfigurations: FunctionConfiguration[]): FunctionDefinition[] => {
  const funcDefList: FunctionDefinition[] = [];

  for (const configuration of functionConfigurations) {
    const funcDef: FunctionDefinition = {};
    funcDef.entry = configuration?.Handler;
    funcDef.name = configuration?.FunctionName;
    funcDef.timeoutSeconds = configuration?.Timeout;
    funcDef.memoryMB = configuration?.MemorySize;
    funcDef.environment = configuration?.Environment;
    funcDef.runtime = configuration?.Runtime;

    funcDefList.push(funcDef);
  }

  return funcDefList;
};
