const inquirer = require('inquirer');

const channelName = 'SMS';

async function run(context) {
  const isChannelEnabled =
    context.exeInfo.serviceMeta.output[channelName] &&
    context.exeInfo.serviceMeta.output[channelName].Enabled;

  if (isChannelEnabled) {
    context.print.info(`The ${channelName} channel is currently enabled`);
    const answer = await inquirer.prompt({
      name: 'disableChannel',
      type: 'confirm',
      message: `Do you want to disable the ${channelName} channel`,
      default: false,
    });
    if (answer.disableChannel) {
      await disableChannel(context);
    }
  } else {
    const answer = await inquirer.prompt({
      name: 'enableChannel',
      type: 'confirm',
      message: `Do you want to enable the ${channelName} channel`,
      default: true,
    });
    if (answer.enableChannel) {
      await enableChannel(context);
    }
  }
}

function enableChannel(context) {
  const params = {
    ApplicationId: context.exeInfo.serviceMeta.output.Id,
    SMSChannelRequest: {
      Enabled: true,
    },
  };
  return new Promise((resolve, reject) => {
    context.exeInfo.pinpointClient.updateSmsChannel(params, (err, data) => {
      if (err) {
        console.log('update channel error');
        reject(err);
      } else {
        console.log(`The ${channelName} channel has been successfully enabled.`);
        context.exeInfo.serviceMeta.output[channelName] = data.SMSChannelResponse;
        resolve(data);
      }
    });
  });
}

function disableChannel(context) {
  const params = {
    ApplicationId: context.exeInfo.serviceMeta.output.Id,
    SMSChannelRequest: {
      Enabled: false,
    },
  };
  return new Promise((resolve, reject) => {
    context.exeInfo.pinpointClient.updateSmsChannel(params, (err, data) => {
      if (err) {
        console.log('update channel error');
        reject(err);
      } else {
        console.log(`The ${channelName} channel has been disabled.`);
        context.exeInfo.serviceMeta.output[channelName] = data.SMSChannelResponse;
        resolve(data);
      }
    });
  });
}


module.exports = {
  run,
};
