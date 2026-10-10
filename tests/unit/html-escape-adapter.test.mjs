import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const createHtmlEscapeAdapter = require('../../src/modules/html-escape-adapter.js');
const adapterSource = readFileSync('src/modules/html-escape-adapter.js', 'utf8');

describe('AppHtml', () => {
  it('stays focused on escaping instead of runtime rendering', () => {
    assert.doesNotMatch(adapterSource, /document\./);
    assert.doesNotMatch(adapterSource, /_rlCtx/);
    assert.doesNotMatch(adapterSource, /renderMap/);
    assert.doesNotMatch(adapterSource, /electronAPI/);
    assert.doesNotMatch(adapterSource, /localStorage/);
  });

  it('escapes HTML-sensitive characters for legacy dashboard callers', () => {
    const html = createHtmlEscapeAdapter();

    assert.equal(
      html.escape(`A&B <tag attr="one">'two'</tag>`),
      'A&amp;B &lt;tag attr=&quot;one&quot;&gt;&#39;two&#39;&lt;/tag&gt;'
    );
    assert.equal(html.escape(null), '');
  });
});
