import assert from 'node:assert';
import { printNodeArray } from '../test_utils/ts_node_printer';
import { generateDataSource } from './source_builder';
describe('Data Category code generation', () => {
  it('generates the correct import', () => {
    const source = printNodeArray(generateDataSource());
    assert.match(source, /import\s?\{\s?defineData\s?\}\s?from\s?"\@aws-amplify\/backend"/);
  });
  describe('import map', () => {
    it('is rendered', () => {
      const tableMapping = { Todo: 'my-todo-mapping' };
      const source = printNodeArray(generateDataSource({ tableMapping }));
      assert.match(source, /importedAmplifyDynamoDBTableMap: \{\s+Todo: ['"]my-todo-mapping['"]/);
    });
    it('shows each key in the mapping table in the `importedModels` array', () => {
      const tables = ['Todo', 'Foo', 'Bar'];
      const tableMapping = tables.reduce((prev, curr) => ({ ...prev, [curr]: 'baz' }), {});
      const source = printNodeArray(generateDataSource({ tableMapping }));
      const array = source.match(/importedModels:\s+\[(.*?)\]/);
      assert.deepEqual(tables, array?.[1].replaceAll('"', '').split(', '));
    });
  });
});
