import { JSONUtilities } from 'amplify-cli-core';
import { getAmplifyLogger, Redactor } from 'amplify-cli-logger';
import { CommandLineInput } from './domain/command-input';

export function logInput(input: CommandLineInput): void {
  getAmplifyLogger().logInfo({
    message: `amplify ${input.command ? input.command : ''} \
${input.plugin ? input.plugin : ''} \
${input.subCommands ? input.subCommands.join(' ') : ''} \
${input.options ? Redactor(JSONUtilities.stringify(input.options, { minify: true })) : ''}`,
  });
}
