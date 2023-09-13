import * as fs from 'fs-extra';

import {
  createNewProjectDir,
  deleteProject,
  deleteProjectDir,
  getNpmPath,
  getNpxPath,
  getScriptRunnerPath,
  initJSProjectWithProfile,
  nspawn,
} from '@aws-amplify/amplify-e2e-core';
import {} from '@aws-amplify/amplify-e2e-core';
import execa from 'execa';
import { spawnSync } from 'child_process';

const nextIndexContent = `export default function Home() {
    return (
      <div>
        {Object.entries(process.env.AWS_EXPORTS).map(
          ([key, value]) => \`\${key}: \${value}\`
        )}
      </div>
    );
  }  
`;

const nextConfigContent = `module.exports = () => {
    const env = {
      AWS_EXPORTS: (() => require("./src/aws-exports"))(),
    };
  
    return { env };
  };  
`;

const es6reactApp = `import { Amplify } from "aws-amplify";
import awsExports from "./aws-exports";

Amplify.configure(awsExports);

function App() {
  return (
    <>
      {Object.entries(awsExports).map(
        ([key, value]) => \`\${key}: \${value}\`
      )}
    </>
  );
}

export default App;
`;

const esmIndex = `import awsExports from './aws-exports.cjs'

console.log(awsExports);
`;

describe('test require on aws-exports file on different JS projects', () => {
  let projRoot: string;

  beforeEach(async () => {
    projRoot = await createNewProjectDir('aws-exports-test');
  });

  afterEach(async () => {
    await deleteProject(projRoot);
    deleteProjectDir(projRoot);
  });

  test('works with commonJS', async () => {
    // init next app
    const appRoot = await createNextApp(projRoot, 'nextjs');

    // install amplify dependency
    spawnSync(getNpmPath(), ['install', '-E', '@aws-amplify/ui-react', 'aws-amplify'], { cwd: appRoot });

    // amplify init, this will generate aws-exports in the project
    await initJSProjectWithProfile(appRoot, { name: 'nextjs' });

    // check if amplify init generated project files
    expect(fs.existsSync(`${appRoot}/amplify/.config/project-config.json`)).toBeTruthy();
    expect(fs.existsSync(`${appRoot}/src/aws-exports.js`)).toBeTruthy();
    expect(fs.existsSync(`${appRoot}/next.config.js`)).toBeTruthy();

    fs.writeFileSync(`${appRoot}/pages/index.js`, nextIndexContent, { encoding: 'utf8', flag: 'w' });
    fs.writeFileSync(`${appRoot}/next.config.js`, nextConfigContent, { encoding: 'utf8', flag: 'w' });

    // this will attempt to compile and nextjs app
    await nspawn(getNpmPath(), ['run', 'build'], { cwd: appRoot })
      .wait(/Compiled successfully/)
      .runAsync();
  });

  test('works with create-react-app', async () => {
    // init react app using create-react-app
    const appRoot = await createReactApp(projRoot, 'es6react');

    // install amplify dependency
    spawnSync(getNpmPath(), ['install', '-E', '@aws-amplify/ui-react', 'aws-amplify'], { cwd: appRoot });

    // amplify init, this will generate aws-exports in the project
    await initJSProjectWithProfile(appRoot, { name: 'es6react' });

    // check if amplify init generated project files
    expect(fs.existsSync(`${appRoot}/amplify/.config/project-config.json`)).toBeTruthy();
    expect(fs.existsSync(`${appRoot}/src/aws-exports.js`)).toBeTruthy();
    expect(fs.existsSync(`${appRoot}/src/App.js`)).toBeTruthy();

    fs.writeFileSync(`${appRoot}/src/App.js`, es6reactApp, { encoding: 'utf8', flag: 'w' });

    await nspawn(getNpmPath(), ['run', 'build'], { cwd: appRoot })
      .wait(/Compiled successfully./)
      .runAsync();
  });

  test('works with esm', async () => {
    // npm init esm package
    spawnSync(getNpmPath(), ['init', '-y'], { cwd: projRoot });
    spawnSync(getNpmPath(), ['pkg', 'set', "'type'='module'"], { cwd: projRoot });

    // install amplify dependency
    spawnSync(getNpmPath(), ['install', '-E', '@aws-amplify/ui-react', 'aws-amplify'], { cwd: projRoot });

    // amplify init, this will generate aws-exports in the project
    await initJSProjectWithProfile(projRoot, { name: 'esm' });

    // check if amplify init generated project files
    expect(fs.existsSync(`${projRoot}/amplify/.config/project-config.json`)).toBeTruthy();
    expect(fs.existsSync(`${projRoot}/src/aws-exports.js`)).toBeTruthy();

    fs.writeFileSync(`${projRoot}/src/index.js`, esmIndex, { encoding: 'utf8', flag: 'w' });

    await nspawn(getScriptRunnerPath(), [`${projRoot}/src/index.js`], { cwd: projRoot }).runAsync();
  });
});

async function createReactApp(cwd: string, projectName: string) {
  const projectRoot = `${cwd}/${projectName}`;

  execa.sync(getNpxPath(), ['create-react-app', '--scripts-version', '5.0.1', projectName, '--use-npm'], { cwd, encoding: 'utf-8' });

  return projectRoot;
}

async function createNextApp(cwd: string, projectName: string) {
  const projectRoot = `${cwd}/${projectName}`;

  execa.sync(getNpxPath(), ['create-next-app', projectName, '--use-npm', '--example', 'basic-export'], {
    cwd,
    encoding: 'utf-8',
  });

  return projectRoot;
}