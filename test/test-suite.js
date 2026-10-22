module.exports = function (DOMPurify, window, tests, xssTests) {
  var document = window.document;
  var jQuery = window.jQuery;

  QUnit.cases(tests).test('Sanitization test', function (params, assert) {
    assert.contains(
      DOMPurify.sanitize(params.payload),
      params.expected,
      'Payload: ' + params.payload
    );
  });

  /* Add compatibility for IE */
  const strRepeat = function (str, num) {
    return new Array(num + 1).join(str);
  }

  QUnit.test('Test proper handling of nesting-based mXSS 1/3', function (assert) {
    let dirty = `${strRepeat(`<div>`, 250)}${strRepeat(`</div>`, 250)}<img>`;
    let expected = `${strRepeat(`<div>`,250)}${strRepeat(`</div>`, 250)}<img>`;
    let clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `${strRepeat(`<div>`, 255)}${strRepeat(`</div>`, 255)}<img>`;
    expected = `${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`;
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `${strRepeat(`<div>`, 257)}${strRepeat(`</div>`, 257)}<img>`;
    expected = `${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`;
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<div><template>${strRepeat(`<div>`, 257)}${strRepeat(`</div>`, 257)}<img>`;
    expected = `<div><template>${strRepeat(`<div>`, 251)}${strRepeat(`</div>`, 251)}<img></template></div>`;
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<div><template>${strRepeat(`<r>`, 255)}<img>${strRepeat(`</r>`, 255)}</template></div><img>`;
    expected = [
      `<div><template></template></div><img>`,
      `<div><template><html><head></head><body></body></html></template></div><img>`,
      `<div><template><head></head><body></body></template></div><img>`,
    ];
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);
  });

  QUnit.test('Test proper handling of nesting-based mXSS 2/3', function (assert) {
    let dirty = `<form><input name="__depth">${strRepeat(`<div>`, 500)}${strRepeat(`</div>`, 500)}<img>`;
    let expected = [
        ``,
        `<form><input name="__depth">${strRepeat(`<div>`, 252)}${strRepeat(`</div>`, 252)}<img></form>`,
    ];
    let clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<form><input name="__depth"></form>${strRepeat(`<div>`, 500)}${strRepeat(`</div>`, 500)}<img>`;
    expected = [
        `${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`,
        `<form><input name="__depth"></form>${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`
    ];
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<form><input name="__removalCount">${strRepeat(`<div>`, 500)}${strRepeat(`</div>`, 500)}<img>`;
    expected = [
      ``,
      `<form><input name="__removalCount">${strRepeat(`<div>`, 252)}${strRepeat(`</div>`, 252)}<img></form>`,
    ];
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<form><input name="__removalCount"></form>${strRepeat(`<div>`, 500)}${strRepeat(`</div>`, 500)}<img>`;
    expected = [
      `${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`,
      `<form><input name="__removalCount"></form>${strRepeat(`<div>`, 253)}${strRepeat(`</div>`, 253)}<img>`,
    ];
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);
  });

  QUnit.test('Test proper handling of nesting-based mXSS 3/3', function (assert) {

    let dirty = `<form><input name="__depth">`;
    let expected = [``, `<form><input name="__depth"></form>`];
    let clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);

    dirty = `<form><input name="__removalCount">`;
    expected = [``, `<form><input name="__removalCount"></form>`];
    clean = DOMPurify.sanitize(dirty);
    assert.contains(clean, expected);
  });

  // Config-Flag Tests
  QUnit.test(
    'Config-Flag tests: KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR',
    function (assert) {
      // KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR
      assert.equal(
        DOMPurify.sanitize('<iframe>Hello</iframe>', { KEEP_CONTENT: false }),
        ''
      );
      assert.contains(
        DOMPurify.sanitize(
          '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
          {
            ALLOWED_TAGS: ['b', 'q'],
            ALLOWED_ATTR: ['style'],
            KEEP_CONTENT: true,
          }
        ),
        [
          'abc<b style="color:red">123</b><q>123</q>',
          'abc<b style="color: red;">123</b><q>123</q>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
          {
            ALLOWED_TAGS: ['b', 'q'],
            ALLOWED_ATTR: ['style'],
            KEEP_CONTENT: false,
          }
        ),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#">abc</a>', {
          ALLOWED_TAGS: ['b', 'q'],
          KEEP_CONTENT: false,
        }),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<form><input name="parentNode"></form>', {
          ALLOWED_TAGS: ['input'],
          KEEP_CONTENT: true,
        }),
        '<input>'
      );
    }
  );
  QUnit.test('Config-Flag tests: ALLOW_DATA_ATTR', function (assert) {
    // ALLOW_DATA_ATTR
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-abc"="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
        ALLOW_DATA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-abc="foo" href="#">abc</a>',
        '<a href="#" data-abc="foo">abc</a>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-abc-1-2-3="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-abc-1-2-3="foo" href="#">abc</a>',
        '<a href="#" data-abc-1-2-3="foo">abc</a>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-""="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-äöü="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a href="#" data-äöü="foo">abc</a>',
        '<a data-äöü="foo" href="#">abc</a>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<a href="#" data-\u00B7._="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      [
        '<a data-\u00B7._="foo" href="#">abc</a>',
        '<a href="#">abc</a>',
        '<a href="#" data-·._="foo">abc</a>',
      ] // IE11 and Edge throw an InvalidCharacterError
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" data-\u00B5="foo">abc</a>', {
        ALLOW_DATA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
  });
  QUnit.test('Config-Flag tests: ADD_TAGS', function (assert) {
    // ADD_TAGS
    assert.equal(
      DOMPurify.sanitize('<my-component>abc</my-component>', {
        ADD_TAGS: ['my-component'],
      }),
      '<my-component>abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent>abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
      }),
      '<my-ĸompønent>abc</my-ĸompønent>'
    );
  });
  QUnit.test('Config-Flag tests: ADD_TAGS + ADD_ATTR', function (assert) {
    // ADD_TAGS + ADD_ATTR
    assert.equal(
      DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
        ADD_TAGS: ['my-component'],
      }),
      '<my-component>abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
        ADD_TAGS: ['my-component'],
        ADD_ATTR: ['my-attr'],
      }),
      '<my-component my-attr="foo">abc</my-component>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
      }),
      '<my-ĸompønent>abc</my-ĸompønent>'
    );
    assert.equal(
      DOMPurify.sanitize('<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>', {
        ADD_TAGS: ['my-ĸompønent'],
        ADD_ATTR: ['my-æŧŧr'],
      }),
      '<my-ĸompønent my-æŧŧr="foo">abc</my-ĸompønent>'
    );
  });
  QUnit.test('Config-Flag tests: SAFE_FOR_JQUERY', function (assert) {
    //SAFE_FOR_JQUERY
    assert.equal(
      DOMPurify.sanitize(
        '<a>123</a><option><style><img src=x onerror=alert(1)>',
        { SAFE_FOR_JQUERY: false }
      ),
      '<a>123</a><option><style><img src=x onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123</a><option><style><img src=x onerror=alert(1)>',
        { SAFE_FOR_JQUERY: true }
      ),
      '<a>123</a><option><style>&lt;img src=x onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>',
        { SAFE_FOR_JQUERY: false }
      ),
      '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>',
        { SAFE_FOR_JQUERY: true }
      ),
      '<option><style>&lt;/option>&lt;/select>&lt;b>&lt;img src=xx: onerror=alert(1)></style></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><iframe></select><b><script>alert(1)</script>',
        { SAFE_FOR_JQUERY: false, KEEP_CONTENT: false }
      ),
      '<option></option>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<option><iframe></select><b><script>alert(1)</script>',
        { SAFE_FOR_JQUERY: true, KEEP_CONTENT: false }
      ),
      '<option></option>'
    );
    assert.equal(
      DOMPurify.sanitize('<b><style><style/><img src=xx: onerror=alert(1)>', {
        SAFE_FOR_JQUERY: false,
      }),
      '<b><style><style/><img src=xx: onerror=alert(1)></style></b>'
    );
    assert.equal(
      DOMPurify.sanitize('<b><style><style/><img src=xx: onerror=alert(1)>', {
        SAFE_FOR_JQUERY: true,
      }),
      '<b><style>&lt;style/>&lt;img src=xx: onerror=alert(1)></style></b>'
    );
    assert.contains(
      DOMPurify.sanitize('1<template><s>000</s></template>2', {
        SAFE_FOR_JQUERY: true,
      }),
      ['1<template><s>000</s></template>2', '1<template></template>2']
    );
    assert.contains(
      DOMPurify.sanitize('<template><s>000</s></template>', {
        SAFE_FOR_JQUERY: true,
      }),
      ['', '<template><s>000</s></template>']
    );
    // see https://github.com/cure53/DOMPurify/issues/283
    assert.equal(
      DOMPurify.sanitize('<i>&amp;amp; &lt;</i>', { SAFE_FOR_JQUERY: true }),
      '<i>&amp;amp; &lt;</i>'
    );
  });
  QUnit.test('Config-Flag tests: SAFE_FOR_TEMPLATES', function (assert) {
    //SAFE_FOR_TEMPLATES
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-bind="style: alert(1)"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-harmless=""></a>', {
        SAFE_FOR_TEMPLATES: true,
        ALLOW_DATA_ATTR: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a data-harmless=""></a>', {
        SAFE_FOR_TEMPLATES: false,
        ALLOW_DATA_ATTR: false,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a> <b><style> </style>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a>123 <b> </b><style> </style>456</a>'
    );
    assert.contains(
      DOMPurify.sanitize(
        '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      ['<b>  </b>', '<b> </b>', '<b> <form><img src="x"></form> </b>']
    );
    assert.contains(
      DOMPurify.sanitize(
        '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      ['<b>he  ya</b>', '<b>he </b>', '<b>he <form><img src="x"></form> ya</b>']
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123<% <b>456}}</b><style>{{ alert(1) }}</style>456 %></a>',
        { SAFE_FOR_TEMPLATES: true }
      ),
      '<a>123 <b> </b><style> </style> </a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="}}javascript:alert(1)"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a class="{{999-333}}"></a>', {
        SAFE_FOR_TEMPLATES: true,
      }),
      '<a class=" "></a>'
    );
    assert.equal(
      DOMPurify.sanitize('{{999-333}}', { SAFE_FOR_TEMPLATES: true }),
      ' '
    );
    assert.equal(
      DOMPurify.sanitize('{<x>{333+333}<x>}', { SAFE_FOR_TEMPLATES: true }),
      ' '
    );
  });
  QUnit.test('Config-Flag tests: SANITIZE_DOM', function (assert) {
    // SANITIZE_DOM
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="implementation">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="createNodeIterator">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="getElementById">', {
        SANITIZE_DOM: false,
      }),
      '<img name="getElementById" src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<img src="x" name="getElementById">', {
        SANITIZE_DOM: true,
      }),
      '<img src="x">'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="x" id="location">click</a>', {
        SANITIZE_DOM: true,
      }),
      '<a href="x">click</a>'
    );
    assert.contains(
      DOMPurify.sanitize('<form><input name="attributes"></form>', {
        ADD_TAGS: ['form'],
        SANITIZE_DOM: false,
      }),
      ['', '<form><input name="attributes"></form>']
    );
    assert.contains(
      DOMPurify.sanitize('<form><input name="attributes"></form>', {
        ADD_TAGS: ['form'],
        SANITIZE_DOM: true,
      }),
      ['', '<form><input name="attributes"></form>', '<form><input></form>']
    );
  });
  QUnit.test('Config-Flag tests: WHOLE_DOCUMENT', function (assert) {
    //WHOLE_DOCUMENT
    assert.equal(DOMPurify.sanitize('123', { WHOLE_DOCUMENT: false }), '123');
    assert.equal(
      DOMPurify.sanitize('123', { WHOLE_DOCUMENT: true }),
      '<html><head></head><body>123</body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: false,
      }),
      ''
    );
    assert.equal(
      DOMPurify.sanitize('<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: true,
      }),
      '<html><head><style>*{color:red}</style></head><body></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('123<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: false,
      }),
      '123<style>*{color:red}</style>'
    );
    assert.equal(
      DOMPurify.sanitize('123<style>*{color:red}</style>', {
        WHOLE_DOCUMENT: true,
      }),
      '<html><head></head><body>123<style>*{color:red}</style></body></html>'
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM', function (assert) {
    //RETURN_DOM
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { RETURN_DOM: true })
        .outerHTML,
      '<body><a>123<b>456</b></a></body>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
        RETURN_DOM: true,
      }).outerHTML,
      '<body><a>123<b>456</b></a></body>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', {
        RETURN_DOM: true,
        WHOLE_DOCUMENT: true,
      }).outerHTML,
      '<html><head></head><body><a>123<b>456</b></a></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
        RETURN_DOM: true,
        WHOLE_DOCUMENT: true,
      }).outerHTML,
      '<html><head></head><body><a>123<b>456</b></a></body></html>'
    );
    assert.equal(
      DOMPurify.sanitize('123', { RETURN_DOM: true }).outerHTML,
      '<body>123</body>'
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM_IMPORT', function (assert) {
    //RETURN_DOM_IMPORT
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM: true }).ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM: true, RETURN_DOM_IMPORT: false })
        .ownerDocument,
      document
    );
    assert.equal(
      DOMPurify.sanitize('123', { RETURN_DOM: true, RETURN_DOM_IMPORT: true })
        .ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', { RETURN_DOM_FRAGMENT: true }).ownerDocument,
      document
    );
    assert.notEqual(
      DOMPurify.sanitize('123', {
        RETURN_DOM_FRAGMENT: true,
        RETURN_DOM_IMPORT: false,
      }).ownerDocument,
      document
    );
    assert.equal(
      DOMPurify.sanitize('123', {
        RETURN_DOM_FRAGMENT: true,
        RETURN_DOM_IMPORT: true,
      }).ownerDocument,
      document
    );
  });
  QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
    //RETURN_DOM_FRAGMENT
    // attempt clobbering
    var fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
      RETURN_DOM_FRAGMENT: true,
    });
    assert.equal(fragment.nodeType, 11);
    assert.notEqual(fragment.ownerDocument, document);
    assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
    // again, but without SANITIZE_DOM
    fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
      RETURN_DOM_FRAGMENT: true,
      SANITIZE_DOM: false,
    });
    assert.equal(fragment.nodeType, 11);
    assert.notEqual(fragment.ownerDocument, document);
    assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
  });
  QUnit.test(
    'Config-Flag tests: SAFE_FOR_TEMPLATES with RETURN_DOM / RETURN_DOM_FRAGMENT',
    function (assert) {
      // Template expressions split across text nodes by removed elements
      // must not survive when the result is returned as DOM
      var hasTemplateExpr = function (str) {
        return (
          str.indexOf('{{') !== -1 ||
          str.indexOf('}}') !== -1 ||
          str.indexOf('<%') !== -1 ||
          str.indexOf('%>') !== -1
        );
      };
      var dirty =
        '<div id="app">{<foo></foo>{constructor.constructor("alert(1)")()}<foo></foo>}</div>';
      // RETURN_DOM
      var dom = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
      });
      assert.ok(!hasTemplateExpr(dom.textContent), dom.textContent);
      assert.equal(dom.outerHTML, '<body> </body>');
      dom = DOMPurify.sanitize('{<x>{333+333}<x>}', {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
      });
      assert.ok(!hasTemplateExpr(dom.textContent), dom.textContent);
      assert.equal(dom.outerHTML, '<body> </body>');
      // RETURN_DOM + RETURN_DOM_IMPORT
      dom = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
        RETURN_DOM_IMPORT: true,
      });
      assert.ok(!hasTemplateExpr(dom.textContent), dom.textContent);
      assert.equal(dom.ownerDocument, document);
      // RETURN_DOM + WHOLE_DOCUMENT
      dom = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM: true,
        WHOLE_DOCUMENT: true,
      });
      assert.ok(!hasTemplateExpr(dom.textContent), dom.textContent);
      // RETURN_DOM_FRAGMENT
      var fragment = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM_FRAGMENT: true,
      });
      assert.equal(fragment.nodeType, 11);
      assert.ok(!hasTemplateExpr(fragment.textContent), fragment.textContent);
      assert.equal(fragment.textContent, ' ');
      fragment = DOMPurify.sanitize('{<x>{333+333}<x>}', {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM_FRAGMENT: true,
      });
      assert.ok(!hasTemplateExpr(fragment.textContent), fragment.textContent);
      // RETURN_DOM_FRAGMENT + RETURN_DOM_IMPORT
      fragment = DOMPurify.sanitize(dirty, {
        SAFE_FOR_TEMPLATES: true,
        RETURN_DOM_FRAGMENT: true,
        RETURN_DOM_IMPORT: true,
      });
      assert.ok(!hasTemplateExpr(fragment.textContent), fragment.textContent);
      // Template-free content is left untouched
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        }).outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
    }
  );
  QUnit.test('Config-Flag tests: IN_PLACE', function (assert) {
    //IN_PLACE
    var dirty = document.createElement('a');
    dirty.setAttribute('href', 'javascript:alert(1)');
    var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
    assert.equal(dirty, clean); // should return the input node
    assert.equal(dirty.href, ''); // should still sanitize
  });
  QUnit.test('Config-Flag tests: FORBID_TAGS', function (assert) {
    //FORBID_TAGS
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['b'] }),
      '<a>123456</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
        FORBID_TAGS: ['a', 'b'],
      }),
      '123456789'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['c'] }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
        FORBID_TAGS: ['script', 'b'],
      }),
      '<a>123456</a>789'
    );
    assert.equal(
      DOMPurify.sanitize('<a>123<b>456</b></a>', {
        ADD_TAGS: ['b'],
        FORBID_TAGS: ['b'],
      }),
      '<a>123456</a>'
    );
  });
  QUnit.test('Config-Flag tests: FORBID_ATTR', function (assert) {
    //FORBID_ATTR
    assert.equal(
      DOMPurify.sanitize('<a x="1">123<b>456</b></a>', { FORBID_ATTR: ['x'] }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a class="0" x="1">123<b y="1">456<script>alert(1)</script></b></a>789',
        { FORBID_ATTR: ['x', 'y'] }
      ),
      '<a class="0">123<b>456</b></a>789'
    );
    assert.equal(
      DOMPurify.sanitize('<a y="1">123<b y="1" y="2">456</b></a>', {
        FORBID_ATTR: ['y'],
      }),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(
        '<a>123<b x="1">456<script y="1">alert(1)</script></b></a>789',
        { FORBID_ATTR: ['x', 'y'] }
      ),
      '<a>123<b>456</b></a>789'
    );
  });
  QUnit.test('Test dirty being an array', function (assert) {
    assert.equal(
      DOMPurify.sanitize(['<a>123<b>456</b></a>']),
      '<a>123<b>456</b></a>'
    );
    assert.equal(
      DOMPurify.sanitize(['<img src=', 'x onerror=alert(1)>']),
      '<img src=",x">'
    );
  });
  // XSS tests: Native DOM methods (alert() should not be called)
  QUnit.cases(xssTests).asyncTest('XSS test: native', function (
    params,
    assert
  ) {
    document.getElementById('qunit-fixture').innerHTML = DOMPurify.sanitize(
      params.payload
    );
    setTimeout(function () {
      QUnit.start();
      assert.notEqual(window.xssed, true, 'alert() was called');
      // Teardown
      document.getElementById('qunit-fixture').innerHTML = '';
      window.xssed = false;
    }, 100);
  });
  // XSS tests: jQuery (alert() should not be called)
  QUnit.cases(xssTests).asyncTest('XSS test: jQuery', function (
    params,
    assert
  ) {
    jQuery('#qunit-fixture').html(
      DOMPurify.sanitize(params.payload, { SAFE_FOR_JQUERY: true })
    );
    setTimeout(function () {
      QUnit.start();
      assert.notEqual(window.xssed, true, 'alert() was called');
      // Teardown
      jQuery('#qunit-fixture').empty();
      window.xssed = false;
    }, 100);
  });
  // document.write tests to handle FF's strange behavior
  QUnit.cases(xssTests).asyncTest(
    'XSS test: document.write() into iframe',
    function (params, assert) {
      var iframe = document.createElement('iframe');
      iframe.src = 'about:blank';
      iframe.onload = function () {
        QUnit.start();
        iframe.contentDocument.write(
          '<script>window.alert=function(){top.xssed=true;}</script>' +
            DOMPurify.sanitize(params.payload)
        );
        assert.notEqual(
          window.xssed,
          true,
          'alert() was called from document.write()'
        );
        window.xssed = false;
        iframe.parentNode.removeChild(iframe);
      };
      document.body.appendChild(iframe);
    }
  );
  // cross-check that document.write into iframe works properly
  QUnit.asyncTest('XSS test: document.write() into iframe', function (assert) {
    window.xssed = false;
    var iframe = document.createElement('iframe');
    iframe.src = 'about:blank';
    iframe.onload = function () {
      QUnit.start();
      iframe.contentDocument.write(
        '<script>window.alert=function(){parent.xssed=true;}</script><script>alert(1);</script>'
      );
      assert.equal(window.xssed, true, 'alert() was called but not detected');
      window.xssed = false;
      iframe.parentNode.removeChild(iframe);
    };
    document.body.appendChild(iframe);
  });
  // Check for isSupported property
  QUnit.test('DOMPurify property tests', function (assert) {
    assert.equal(typeof DOMPurify.isSupported, 'boolean');
  });
  // Test with a custom window object
  QUnit.test('DOMPurify custom window tests', function (assert) {
    assert.strictEqual(typeof DOMPurify(null).version, 'string');
    assert.strictEqual(DOMPurify(null).isSupported, false);
    assert.strictEqual(DOMPurify(null).sanitize, undefined);
    assert.strictEqual(typeof DOMPurify({}).version, 'string');
    assert.strictEqual(DOMPurify({}).isSupported, false);
    assert.strictEqual(DOMPurify({}).sanitize, undefined);
    assert.strictEqual(
      typeof DOMPurify({ document: 'not really a document' }).version,
      'string'
    );
    assert.strictEqual(
      DOMPurify({ document: 'not really a document' }).isSupported,
      false
    );
    assert.strictEqual(
      DOMPurify({ document: 'not really a document' }).sanitize,
      undefined
    );
    assert.strictEqual(typeof DOMPurify(window).version, 'string');
    assert.strictEqual(typeof DOMPurify(window).sanitize, 'function');
  });
  // Test to prevent security issues with pre-clobbered DOM
  QUnit.test(
    'sanitize() should not throw if the original document is clobbered _after_ DOMPurify has been instantiated',
    function (assert) {
      var evilNode = document.createElement('div');
      evilNode.innerHTML =
        '<img id="implementation"><img id="createNodeIterator"><img id="importNode"><img id="createElement">';
      document.body.appendChild(evilNode);
      try {
        // tests implementation and createNodeIterator
        var resultPlain = DOMPurify.sanitize('123');
        // tests importNode
        var resultImport = DOMPurify.sanitize('123', {
          RETURN_DOM: true,
          RETURN_DOM_IMPORT: true,
        });
        // tests createElement
        var resultBody = DOMPurify.sanitize('123<img id="body">');
      } finally {
        // clean up before doing the actual assertions, otherwise qunit/jquery/etc might blow up
        document.body.removeChild(evilNode);
      }
      assert.equal(resultPlain, '123');
      assert.equal(resultImport.ownerDocument, document);
      assert.equal(resultBody, '123<img>');
    }
  );
  // Test to check against a hang in MSIE (#89)
  QUnit.test(
    'sanitize() should not hang on MSIE when hook changes textContent',
    function (assert) {
      DOMPurify.addHook('afterSanitizeElements', function (node) {
        if (node.nodeType && node.nodeType === document.TEXT_NODE) {
          node.textContent = 'foo';
        }
        return node;
      });
      var dirty =
        '<div><p>This is a beatufiul text</p><p>This is too</p></div>';
      var modified = '<div><p>foo</p><p>foo</p></div>';
      assert.equal(DOMPurify.sanitize(dirty), modified);
      DOMPurify.removeHooks('afterSanitizeElements');
    }
  );
  // Tests to ensure that a configuration can be set and cleared
  QUnit.test(
    'ensure that a persistent configuration can be set and cleared',
    function (assert) {
      var dirty = '<my-component>abc</my-component>';
      assert.equal(DOMPurify.sanitize(dirty), 'abc');
      DOMPurify.setConfig({ ADD_TAGS: ['my-component'] });
      assert.equal(
        DOMPurify.sanitize(dirty),
        '<my-component>abc</my-component>'
      );
      DOMPurify.clearConfig();
      assert.equal(DOMPurify.sanitize(dirty), 'abc');
    }
  );
  // Test to ensure that a hook can add allowed tags / attributes on the fly
  QUnit.test(
    'ensure that a hook can add allowed tags / attributes on the fly',
    function (assert) {
      DOMPurify.addHook('uponSanitizeElement', function (node, data) {
        if (
          node.nodeName &&
          node.nodeName.match(/^\w+-\w+$/) &&
          !data.allowedTags[data.tagName]
        ) {
          data.allowedTags[data.tagName] = true;
        }
      });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (
          data.attrName &&
          data.attrName.match(/^\w+-\w+$/) &&
          !data.allowedAttributes[data.attrName]
        ) {
          data.allowedAttributes[data.attrName] = true;
        }
      });
      var dirty =
        '<p>HE<iframe></iframe><is-custom onload="alert(1)" super-custom="test" />LLO</p>';
      var modified = '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
      assert.equal(DOMPurify.sanitize(dirty), modified);
      DOMPurify.removeHooks('uponSanitizeElement');
      DOMPurify.removeHooks('uponSanitizeAttribute');
    }
  );
  // Test to ensure that if input[type=file] is badlisted and flagged as an
  // attribute not to keep via hookEvent.keepAttr, it should be removed despite
  // it being an issue of being able to programmatically add it back in Safari.
  QUnit.test(
    'ensure that input[type=file] is removed via hookEvent keepAttr',
    function (assert) {
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (
          node.nodeName == 'INPUT' &&
          node.getAttribute('type') &&
          node.getAttribute('type') == 'file'
        ) {
          data.keepAttr = false;
        }
      });
      var dirty = '<input type="file" />';
      var modified = '<input>';
      if (window.name == 'nodejs') {
        assert.equal(DOMPurify.sanitize(dirty), modified);
      } else {
        assert.expect(0);
      }
      DOMPurify.removeHooks('uponSanitizeAttribute');
    }
  );

  // -------------------------------------------------------------------
  // The allowlists are handed to the uponSanitize* hooks by reference (as
  // data.allowedTags / data.allowedAttributes), so a hook that widens them
  // - the documented in-call widening pattern - used to mutate the shared,
  // module-level set: the widening leaked into every later sanitize() call.
  // The guard clones the sets per walk, on both config paths (the per-call
  // path and the persistent setConfig() path). (GHSA-cmwh-pvxp-8882)
  // -------------------------------------------------------------------

  QUnit.test(
    'default config: attribute hook does not poison later calls',
    function (assert) {
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        // A trusted element widens onerror for its own call.
        assert.ok(
          DOMPurify.sanitize(
            '<img data-trusted="1" src="x" onerror="ok()">'
          ).indexOf('onerror') !== -1,
          'in-call widening works for the trusted element'
        );

        // A later untrusted call must NOT inherit the widened attribute.
        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '<img src="x">',
          'untrusted call after trusted render strips onerror'
        );

        // Repeated calls must stay clean (no accumulated clone state).
        for (var i = 0; i < 5; i++) {
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
            '<img src="x">',
            'repeated untrusted call ' + i + ' stays clean'
          );
        }
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    }
  );

  QUnit.test(
    'default config: element hook does not poison later calls',
    function (assert) {
      DOMPurify.addHook('uponSanitizeElement', function (node, data) {
        if (
          node.getAttribute &&
          node.getAttribute('data-trusted') === '1' &&
          data.allowedTags
        ) {
          data.allowedTags['bogus-tag'] = true;
        }
      });

      try {
        assert.ok(
          DOMPurify.sanitize(
            '<div data-trusted="1"><bogus-tag>abc</bogus-tag></div>'
          ).indexOf('bogus-tag') !== -1,
          'in-call widening works for the trusted element'
        );

        assert.equal(
          DOMPurify.sanitize('<bogus-tag>abc</bogus-tag>'),
          'abc',
          'untrusted <bogus-tag> not allowed after trusted render'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeElement');
      }
    }
  );

  // -------------------------------------------------------------------
  // Persistent-config path (setConfig). sanitize() skips _parseConfig once
  // setConfig() has run, so the sets are not re-derived per call: a hook
  // write to data.allowedAttributes would mutate the allowlist for the
  // instance lifetime, across calls and elements. The guard is applied on
  // every sanitize() call for both config paths. (GHSA-cmwh-pvxp-8882)
  // -------------------------------------------------------------------

  QUnit.test(
    'setConfig: attribute hook does not poison later calls',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        // A trusted element widens onerror for its own call.
        assert.ok(
          DOMPurify.sanitize(
            '<img data-trusted="1" src="x" onerror="ok()">'
          ).indexOf('onerror') !== -1,
          'in-call widening works for the trusted element under setConfig'
        );

        // A later untrusted call must NOT inherit the widened attribute.
        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '<img src="x">',
          'untrusted call after trusted render strips onerror'
        );

        // Repeated calls must stay clean (no accumulated clone state).
        for (var i = 0; i < 5; i++) {
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
            '<img src="x">',
            'repeated untrusted call ' + i + ' stays clean'
          );
        }
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
        DOMPurify.clearConfig();
      }
    }
  );

  QUnit.test(
    'setConfig: element hook does not poison later calls',
    function (assert) {
      DOMPurify.setConfig({ ALLOWED_TAGS: ['span'], ALLOWED_ATTR: [] });
      DOMPurify.addHook('uponSanitizeElement', function (node, data) {
        if (
          node.getAttribute &&
          node.getAttribute('data-trusted') === '1' &&
          data.allowedTags
        ) {
          data.allowedTags['img'] = true;
        }
      });

      try {
        DOMPurify.sanitize('<span data-trusted="1"><img src="x"></span>');

        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
          '',
          'untrusted <img> not allowed after trusted render under setConfig'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeElement');
        DOMPurify.clearConfig();
      }
    }
  );

  QUnit.test('setConfig: clearConfig restores a clean state', function (
    assert
  ) {
    DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
    DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
      if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
        data.allowedAttributes['onerror'] = true;
      }
    });

    try {
      DOMPurify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

      DOMPurify.clearConfig();

      assert.equal(
        DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
        '<img src="x">',
        'default-cfg call after clearConfig strips onerror'
      );
    } finally {
      DOMPurify.removeHooks('uponSanitizeAttribute');
      DOMPurify.clearConfig();
    }
  });

  QUnit.test(
    'reused config object: attribute hook does not poison later calls',
    function (assert) {
      // The parsed config is handed to hooks as their third argument, so a
      // caller can pass it straight back into sanitize(); _parseConfig then
      // returns early without re-deriving the sets.
      var seenConfig = null;
      DOMPurify.addHook('uponSanitizeAttribute', function (node, data, cfg) {
        seenConfig = cfg;
        if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
          data.allowedAttributes['onerror'] = true;
        }
      });

      try {
        var config = { ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] };
        assert.ok(
          DOMPurify.sanitize(
            '<img data-trusted="1" src="x" onerror="ok()">',
            config
          ).indexOf('onerror') !== -1,
          'in-call widening works for the trusted element'
        );
        assert.ok(seenConfig, 'the hook received the parsed config object');

        assert.equal(
          DOMPurify.sanitize('<img src="x" onerror="alert(1)">', seenConfig),
          '<img src="x">',
          'reusing the parsed config object does not inherit onerror'
        );
      } finally {
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    }
  );

  // -------------------------------------------------------------------
  // The hooks registry is a plain object, so an unknown entry point such
  // as '__proto__' used to resolve off the prototype chain and arrayPush
  // then wrote to Object.prototype. (GHSA-cmwh-pvxp-8882)
  // -------------------------------------------------------------------

  QUnit.test(
    'addHook ignores unknown entry points and does not pollute Object.prototype',
    function (assert) {
      var hookFunction = function () {};

      try {
        DOMPurify.addHook('__proto__', hookFunction);

        assert.equal(
          {}.length,
          undefined,
          'Object.prototype.length was not created'
        );
        assert.equal({}[0], undefined, 'Object.prototype[0] was not created');
        assert.equal([].length, 0, 'Array.prototype was not affected');

        // Unknown entry points are ignored, not thrown on.
        DOMPurify.addHook('constructor', hookFunction);
        DOMPurify.addHook('notAHook', hookFunction);
        assert.equal(
          DOMPurify.removeHook('__proto__'),
          undefined,
          'removeHook on an unknown entry point returns undefined'
        );
        DOMPurify.removeHooks('__proto__');
        assert.equal(
          {}.length,
          undefined,
          'Object.prototype still untouched after removeHook(s)'
        );

        // Real hooks keep working.
        DOMPurify.addHook('afterSanitizeAttributes', function (node) {
          if (node.setAttribute) {
            node.setAttribute('class', 'world');
          }
        });
        assert.equal(
          DOMPurify.sanitize('<div class="hello"></div>'),
          '<div class="world"></div>',
          'known entry points are still registered'
        );
      } finally {
        DOMPurify.removeHooks('afterSanitizeAttributes');
        delete Object.prototype[0];
        delete Object.prototype.length;
      }
    }
  );

  // -------------------------------------------------------------------
  // USE_PROFILES used to reset ALLOWED_ATTR to a plain array, which only
  // lost its prototype once a profile (or ADD_ATTR) added attributes to
  // it. With no attribute-bearing profile enabled, a polluted
  // Object.prototype / Array.prototype key such as `onerror` was then
  // treated as an allowed attribute. (CVE-2026-65913)
  // -------------------------------------------------------------------

  QUnit.test(
    'USE_PROFILES: allowed attributes are not inherited from polluted prototypes',
    function (assert) {
      var dirty = '<img src="x" onerror="alert(1)">';
      // Without an explicit FORBID_ATTR the default FORBID_ATTR is a plain
      // object that inherits the polluted key as well, so the configs that
      // set FORBID_ATTR are the ones that reach ALLOWED_ATTR through a
      // polluted Object.prototype.
      var configs = [
        { USE_PROFILES: {}, ADD_TAGS: ['img'] },
        { USE_PROFILES: {}, ADD_TAGS: ['img'], FORBID_ATTR: ['style'] },
        { USE_PROFILES: { html: false }, ADD_TAGS: ['img'] },
        {
          USE_PROFILES: { html: false },
          ADD_TAGS: ['img'],
          FORBID_ATTR: ['style'],
        },
        { USE_PROFILES: { svg: false, mathMl: false }, ADD_TAGS: ['img'] },
        { USE_PROFILES: { html: true } },
        { USE_PROFILES: { html: true }, FORBID_ATTR: ['style'] },
      ];
      var prototypes = [
        ['Object.prototype', Object.prototype],
        ['Array.prototype', Array.prototype],
      ];
      prototypes.forEach(function (proto) {
        configs.forEach(function (config) {
          var clean;
          var label = proto[0] + '.onerror = true, ' + JSON.stringify(config);
          proto[1].onerror = true;
          try {
            clean = DOMPurify.sanitize(dirty, config);
          } finally {
            delete proto[1].onerror;
          }

          assert.equal(
            clean.indexOf('onerror'),
            -1,
            label + ': onerror is removed, got ' + clean
          );
          assert.equal(
            clean.indexOf('<img'),
            0,
            label + ': <img> is kept, got ' + clean
          );
        });
      });
    }
  );

  // -------------------------------------------------------------------
  // FORBID_ATTR is documented to override every allow rule, but the
  // ALLOW_DATA_ATTR and ALLOW_ARIA_ATTR branches used to accept data-* and
  // aria-* attributes before FORBID_ATTR was consulted. (CVE-2026-65913)
  // -------------------------------------------------------------------

  QUnit.test(
    'FORBID_ATTR always wins over ALLOW_DATA_ATTR, ALLOW_ARIA_ATTR and ADD_ATTR',
    function (assert) {
      assert.equal(
        DOMPurify.sanitize('<div data-foo="1" data-bar="2">abc</div>', {
          FORBID_ATTR: ['data-foo'],
        }),
        '<div data-bar="2">abc</div>',
        'forbidden data-* is removed with the default ALLOW_DATA_ATTR'
      );
      assert.equal(
        DOMPurify.sanitize('<div data-foo="1">abc</div>', {
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ['data-foo'],
        }),
        '<div>abc</div>',
        'forbidden data-* is removed with an explicit ALLOW_DATA_ATTR'
      );
      assert.equal(
        DOMPurify.sanitize('<div data-foo="1">abc</div>', {
          ADD_ATTR: ['data-foo'],
          FORBID_ATTR: ['data-foo'],
        }),
        '<div>abc</div>',
        'forbidden data-* is removed even when listed in ADD_ATTR'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-label="x">abc</a>', {
          FORBID_ATTR: ['aria-label'],
        }),
        '<a href="#">abc</a>',
        'forbidden aria-* is removed with the default ALLOW_ARIA_ATTR'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-label="x">abc</a>', {
          ALLOW_ARIA_ATTR: true,
          FORBID_ATTR: ['ARIA-LABEL'],
        }),
        '<a href="#">abc</a>',
        'forbidden aria-* is removed with an explicit ALLOW_ARIA_ATTR'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" aria-label="x">abc</a>', {
          FORBID_ATTR: ['data-foo'],
        }),
        [
          '<a href="#" aria-label="x">abc</a>',
          '<a aria-label="x" href="#">abc</a>',
        ],
        'aria-* that is not forbidden is still kept'
      );

      DOMPurify.setConfig({ FORBID_ATTR: ['data-foo', 'aria-label'] });
      try {
        assert.strictEqual(
          DOMPurify.isValidAttribute('div', 'data-foo', '1'),
          false,
          'isValidAttribute rejects a forbidden data-* attribute'
        );
        assert.strictEqual(
          DOMPurify.isValidAttribute('div', 'aria-label', 'x'),
          false,
          'isValidAttribute rejects a forbidden aria-* attribute'
        );
        assert.strictEqual(
          DOMPurify.isValidAttribute('div', 'data-bar', '1'),
          true,
          'isValidAttribute still accepts a data-* attribute that is not forbidden'
        );
      } finally {
        DOMPurify.clearConfig();
      }
    }
  );

  // -------------------------------------------------------------------
  // Sanitized markup that is later re-inserted into a raw text wrapper
  // (e.g. sink.innerHTML = '<xmp>' + clean + '</xmp>') must not be able
  // to close that wrapper and smuggle live markup (CVE-2026-65914).
  // -------------------------------------------------------------------

  var reContextWrappers = [
    'script',
    'xmp',
    'textarea',
    'noscript',
    'iframe',
    'noembed',
    'noframes',
    'style',
    'title',
  ];

  /* Re-parse sanitized markup inside a wrapper element (sink roundtrip) and
   * count the elements carrying an event handler that come to life */
  var liveHandlersInWrapper = function (wrapper, clean) {
    var doc = document.implementation.createHTMLDocument('');
    doc.body.innerHTML = '<' + wrapper + '>' + clean + '</' + wrapper + '>';
    return doc.querySelectorAll('[onerror]').length;
  };

  QUnit.test(
    'Test against mXSS via re-contextualization of attribute values',
    function (assert) {
      reContextWrappers.forEach(function (wrapper) {
        var dirty =
          '<img src="x" alt="</' +
          wrapper +
          '><img src=x onerror=alert(1)>">';
        var clean = DOMPurify.sanitize(dirty);
        assert.equal(
          clean,
          '<img src="x">',
          'attribute closing </' + wrapper + '> is removed: ' + clean
        );
        assert.equal(
          liveHandlersInWrapper(wrapper, clean),
          0,
          'no live handler after re-parsing inside <' + wrapper + '>: ' + clean
        );
        assert.equal(
          DOMPurify.sanitize(
            '<img src="x" alt="</' + wrapper.toUpperCase() + ' >">'
          ),
          '<img src="x">',
          'end tag check is case-insensitive for ' + wrapper
        );
      });
      assert.equal(
        DOMPurify.sanitize(
          '<a href="#" title="a &lt;/xmp&gt; b">x</a><img alt="--><img src=x onerror=alert(1)>"><img alt="--!><img src=x onerror=alert(1)>"><img alt="]]><img src=x onerror=alert(1)>">'
        ),
        '<a href="#">x</a><img><img><img>',
        'comment and CDATA closers inside attributes are removed'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" alt="</div> <b>bold</b> -> ok">'),
        DOMPurify.sanitize('<img src="x" alt="</div> <b>bold</b> -> ok">', {
          SAFE_FOR_XML: true,
        }),
        'SAFE_FOR_XML is enabled by default'
      );
      assert.notEqual(
        DOMPurify.sanitize('<img src="x" alt="</div> <b>bold</b> -> ok">')
          .indexOf('alt='),
        -1,
        'harmless markup inside attributes is kept'
      );
      assert.notEqual(
        DOMPurify.sanitize(
          '<img src="x" alt="</xmp><img src=x onerror=alert(1)>">',
          { SAFE_FOR_XML: false }
        ).indexOf('alt='),
        -1,
        'SAFE_FOR_XML: false keeps the attribute'
      );
    }
  );
  QUnit.test(
    'Test against mXSS via re-contextualization of raw text content',
    function (assert) {
      reContextWrappers.forEach(function (wrapper) {
        if (wrapper === 'style') {
          return;
        }

        var dirty =
          '<p>a<style></' +
          wrapper +
          '><img src=x onerror=alert(1)></style></p>';
        var clean = DOMPurify.sanitize(dirty);
        assert.equal(
          clean,
          '<p>a</p>',
          'style text closing </' + wrapper + '> is removed: ' + clean
        );
        assert.equal(
          liveHandlersInWrapper(wrapper, clean),
          0,
          'no live handler after re-parsing inside <' + wrapper + '>: ' + clean
        );
      });
      reContextWrappers.forEach(function (wrapper) {
        var clean = DOMPurify.sanitize(
          '<p>a<!--</' + wrapper + '><img src=x onerror=alert(1)>--></p>',
          { ADD_TAGS: ['#comment'] }
        );
        assert.equal(
          clean,
          '<p>a</p>',
          'comment closing </' + wrapper + '> is removed: ' + clean
        );
        assert.equal(
          liveHandlersInWrapper(wrapper, clean),
          0,
          'no live handler after re-parsing inside <' + wrapper + '>: ' + clean
        );
      });
      assert.equal(
        DOMPurify.sanitize('<p>a<style>*{color:red}</style></p>'),
        '<p>a<style>*{color:red}</style></p>',
        'harmless style content is kept'
      );
      assert.equal(
        DOMPurify.sanitize('<p>a<!-- hello --></p>', {
          ADD_TAGS: ['#comment'],
        }),
        '<p>a<!-- hello --></p>',
        'harmless comments are kept'
      );
      assert.equal(
        DOMPurify.sanitize('<p>&lt;/xmp&gt;<textarea></xmp></textarea></p>'),
        '<p>&lt;/xmp&gt;<textarea>&lt;/xmp&gt;</textarea></p>',
        'escaped text is kept'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<p>a<style></xmp><img src=x onerror=alert(1)></style></p>',
          { SAFE_FOR_XML: false }
        ),
        '<p>a<style></xmp><img src=x onerror=alert(1)></style></p>',
        'SAFE_FOR_XML: false keeps the raw text'
      );
    }
  );
  QUnit.test(
    'sanitize() should allow unknown protocols when ALLOW_UNKNOWN_PROTOCOLS is true',
    function (assert) {
      var dirty =
        '<div><a href="spotify:track:12345"><img src="cid:1234567"></a></div>';
      assert.equal(
        dirty,
        DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
      );
    }
  );

  QUnit.test(
    'sanitize() should not allow javascript when ALLOW_UNKNOWN_PROTOCOLS is true',
    function (assert) {
      var dirty =
        '<div><a href="javascript:alert(document.title)"><img src="cid:1234567"/></a></div>';
      var modified = '<div><a><img src="cid:1234567"></a></div>';
      assert.equal(
        modified,
        DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
      );
    }
  );

  QUnit.test('Regression-Test to make sure #166 stays fixed', function (
    assert
  ) {
    var dirty = '<p onFoo="123">HELLO</p>';
    var modified = '<p>HELLO</p>';
    assert.equal(
      modified,
      DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
    );
  });

  // Test 1 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should contain one element', function (assert) {
    var dirty =
      '<svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 1);
  });

  // Test 2 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should contain two elements', function (
    assert
  ) {
    var dirty =
      '1<script>alert(1)</script><svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 2);
  });

  // Test 3 to check if the element count in DOMPurify.removed is correct
  QUnit.test('DOMPurify.removed should be correct', function (assert) {
    var dirty = '<img src=x onerror="alert(1)">';
    DOMPurify.sanitize(dirty);
    assert.equal(DOMPurify.removed.length, 1);
  });

  // Test 4 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<a>123{{456}}</a>';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 5 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<a>123{{456}}<b>456{{789}}</b></a>';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 2);
    }
  );

  // Test 6 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
    function (assert) {
      var dirty = '<img src=1 width="{{123}}">';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 7 to check that DOMPurify.removed is correct in SAFE_FOR_JQUERY mode
  QUnit.test(
    'DOMPurify.removed should be correct in SAFE_FOR_JQUERY mode',
    function (assert) {
      var dirty = '<option><iframe></select><b><script>alert(1)</script>';
      DOMPurify.sanitize(dirty, { SAFE_FOR_JQUERY: true });
      assert.equal(DOMPurify.removed.length, 1);
    }
  );

  // Test 8 to check that DOMPurify.removed is correct if tags are clean
  QUnit.test(
    'DOMPurify.removed should not contain elements if tags are permitted',
    function (assert) {
      var dirty = '<a>123</a>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 9 to check that DOMPurify.removed is correct if the tags and attributes are clean
  QUnit.test(
    'DOMPurify.removed should not contain elements if all tags and attrs are permitted',
    function (assert) {
      var dirty = '<img src=x>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 10 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_TEMLATES mode
  QUnit.test(
    'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_TEMLATES mode',
    function (assert) {
      var dirty = '1';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_TEMPLATES: true,
      });
      assert.equal(DOMPurify.removed.length, 0);
    }
  );

  // Test 11 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_JQUERY mode
  QUnit.test(
    'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_JQUERY mode',
    function (assert) {
      var dirty = '1';
      DOMPurify.sanitize(dirty, {
        WHOLE_DOCUMENT: true,
        SAFE_FOR_JQUERY: true,
      });
      assert.equal(DOMPurify.removed.length, 0);
    }
  );
  // Tests to make sure that the node scanning feature delivers acurate results on all browsers
  QUnit.test(
    'DOMPurify should deliver acurate results when sanitizing nodes 1',
    function (assert) {
      var clean = DOMPurify.sanitize(document.createElement('td'));
      assert.equal(clean, '<td></td>');
    }
  );
  QUnit.test(
    'DOMPurify should deliver accurate results when sanitizing nodes 2',
    function (assert) {
      var clean = DOMPurify.sanitize(document.createElement('td'), {
        RETURN_DOM: true,
      });
      assert.equal(clean.outerHTML, '<body><td></td></body>');
    }
  );
  // Test to make sure that URI_safe attributes can be configured too
  QUnit.test('DOMPurify should allow to define URI safe attributes', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
      ADD_URI_SAFE_ATTR: ['typeof'],
    });
    assert.equal(clean, '<b typeof="bla:h">123</b>');
  });
  // Test to make sure that URI_safe attributes don't persist, see #327
  QUnit.test('DOMPurify should not persist URI safe attributes', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
      ADD_URI_SAFE_ATTR: ['typeof'],
    });
    var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
      ALLOWED_ATTR: ['typeof'],
    });
    assert.equal(clean, '<b>123</b>');
  });
  // Test to make sure that URI_safe attributes don't overwrite default, see #366
  QUnit.test(
    'DOMPurify should not overwrite default URI safe attributes',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<div poster="x:y" style="color: red">Test</div>',
        { ADD_URI_SAFE_ATTR: ['poster'] }
      );
      assert.contains(clean, [
        '<div style="color: red" poster="x:y">Test</div>',
        '<div style="color: red;" poster="x:y">Test</div>',
      ]);

      clean = DOMPurify.sanitize(
        '<div poster="x:y" style="color: red">Test</div>'
      );
      assert.contains(clean, [
        '<div style="color: red">Test</div>',
        '<div style="color: red;">Test</div>',
      ]);
    }
  );
  // Test to make sure that empty HTML doesn't return null on MSIE11 (#198)
  QUnit.test(
    "Empty HTML shouldn't return null on MSIE11 in RETURN_DOM_FRAGMENT mode",
    function (assert) {
      var clean = DOMPurify.sanitize('', {
        RETURN_DOM: true,
        RETURN_DOM_FRAGMENT: true,
      });
      assert.equal(typeof clean, 'object');
    }
  );
  // Tests to make sure that FORCE_BODY pushes elements to document.body (#199)
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize('<style>123</style>', {
        FORCE_BODY: true,
      });
      assert.equal(clean, '<style>123</style>');
    }
  );
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize('<script>123</script>', {
        FORCE_BODY: true,
        ADD_TAGS: ['script'],
      });
      assert.equal(clean, '<script>123</script>');
    }
  );
  QUnit.test(
    'FORCE_BODY needs to push some elements to document.body',
    function (assert) {
      var clean = DOMPurify.sanitize(' AAAAA', { FORCE_BODY: true });
      assert.equal(clean, ' AAAAA');
    }
  );
  QUnit.test('Lack of FORCE_BODY still preserves leading whitespace', function (
    assert
  ) {
    var clean = DOMPurify.sanitize(' <b>AAAAA</b>', { FORCE_BODY: false });
    assert.equal(clean, ' <b>AAAAA</b>');
  });
  QUnit.test(
    'Lack of FORCE_BODY needs to push some elements to document.head',
    function (assert) {
      var clean = DOMPurify.sanitize('<style>123</style>', {
        FORCE_BODY: false,
      });
      assert.equal(clean, '');
    }
  );
  // Test to make sure that ALLOW_ARIA_ATTR is working as expected (#198)
  QUnit.test('Config-Flag tests: ALLOW_ARIA_ATTR', function (assert) {
    assert.contains(
      DOMPurify.sanitize('<a aria-abc="foo" href="#">abc</a>', {
        ALLOW_ARIA_ATTR: true,
      }),
      [
        '<a aria-abc="foo" href="#">abc</a>',
        '<a href="#" aria-abc="foo">abc</a>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-aöü="foo">abc</a>', {
        ALLOW_ARIA_ATTR: true,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-abc="foo">abc</a>', {
        ALLOW_ARIA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
    assert.equal(
      DOMPurify.sanitize('<a href="#" aria-äöü="foo">abc</a>', {
        ALLOW_ARIA_ATTR: false,
      }),
      '<a href="#">abc</a>'
    );
  });
  QUnit.test('Config-Flag tests: USE_PROFILES', function (assert) {
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: false } }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: true } }),
      '<h1>HELLO</h1>'
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math></math>', {
        USE_PROFILES: { html: true, mathMl: true },
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math><mi></mi></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
        FORBID_TAGS: ['mi'],
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math></math>']
    );
    assert.contains(
      DOMPurify.sanitize('<h1>HELLO</h1><math class="foo"><mi></mi></math>', {
        USE_PROFILES: { html: true, mathMl: true },
        FORBID_ATTR: ['class'],
      }),
      ['<h1>HELLO</h1>', '<h1>HELLO</h1><math><mi></mi></math>']
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { bogus: true } }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: 123 }),
      'HELLO'
    );
    assert.equal(
      DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: [] }),
      'HELLO'
    );
    assert.contains(
      DOMPurify.sanitize('<svg><rect height="50"></rect></svg>', {
        USE_PROFILES: { svg: true },
      }),
      [
        '',
        '<svg><rect height="50"></rect></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><rect height="50" /></svg>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<feBlend in="SourceGraphic" mode="multiply" />', {
        USE_PROFILES: { svgFilters: true },
      }),
      [
        '<feblend in="SourceGraphic" mode="multiply"></feblend>',
        '<feblend mode="multiply" in="SourceGraphic"></feblend>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<svg><style>.some-class {fill: #fff}</style></svg>', {
        USE_PROFILES: { svg: true },
      }),
      [
        '',
        '<svg><style>.some-class {fill: #fff}</style></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><style>.some-class {fill: #fff}</style></svg>',
      ]
    );
    assert.contains(
      DOMPurify.sanitize('<svg><text>SEE ME</text></svg>', {
        USE_PROFILES: { svg: true },
        KEEP_CONTENT: false,
      }),
      [
        '',
        '<svg><text>SEE ME</text></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg"><text>SEE ME</text></svg>',
      ]
    );
    assert.equal(
      DOMPurify.sanitize('<span>SEE ME</span>', {
        USE_PROFILES: { html: true },
        KEEP_CONTENT: false,
      }),
      '<span>SEE ME</span>'
    );
    assert.equal(
      DOMPurify.sanitize('<div></div>', {
        USE_PROFILES: { svg: true },
        ADD_TAGS: ['div'],
      }),
      '<div></div>'
    );
    assert.contains(
      DOMPurify.sanitize('<svg keep="me"></svg>', {
        USE_PROFILES: { svg: true },
        ADD_ATTR: ['keep'],
      }),
      [
        '',
        '<svg keep="me"></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg" keep="me" />',
      ]
    );
  });
  QUnit.test('Config-Flag tests: ALLOWED_URI_REGEXP', function (assert) {
    var tests = [
      {
        test: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
        expected: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
      },
      {
        test: '<img src="http://i.imgur.com/WScAnHr.jpg">',
        expected: '<img src="http://i.imgur.com/WScAnHr.jpg">',
      },
      {
        test:
          '<img src="blob:https://localhost:3000/c4ea3ec6-9f22-4d08-af6f-d79e78a0a7a7">',
        expected: '<img>',
      },
      {
        test: '<a href="mailto:demo@example.com">demo</a>',
        expected: '<a>demo</a>',
      },
    ].forEach(function (test) {
      var str = DOMPurify.sanitize(test.test, {
        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
      });
      assert.equal(str, test.expected);
    });
  });
  QUnit.test('Avoid freeze when using tables and ALLOW_TAGS', function (
    assert
  ) {
    var clean = DOMPurify.sanitize('<table><tr><td></td></tr></table>', {
      ALLOW_TAGS: ['table', 'tr', 'td'],
    });
    assert.equal(clean, '<table><tbody><tr><td></td></tr></tbody></table>');
  });
  QUnit.test(
    'Avoid XSS with ALLOW_TAGS permitting noembed, noscript',
    function (assert) {
      var clean = DOMPurify.sanitize(
        "a<noembed><p id='</noembed><img src=x onerror=alert(1)>'></p></noembed>",
        { ADD_TAGS: ['noembed'] }
      );
      assert.contains(clean, [
        'a<noembed><p id=\'</noembed><img src="x">\'&gt;<p></p>',
        'a',
        'a<noembed>&lt;p id=\'</noembed><img src="x">\'&gt;<p></p>',
        'a<noembed><p id="&lt;/noembed&gt;&lt;img src=x onerror=alert(1)&gt;"></p></noembed>',
        'a<noembed></noembed>',
      ]);
    }
  );
  QUnit.test('Avoid mXSS in Chrome 77 and above using SVG', function (assert) {
    var clean = DOMPurify.sanitize('<svg></p><style><g title="</style>');
    assert.contains(clean, [
      '',
      '<svg><p></p><style></style></svg>',
      '<svg></svg><p></p><style><g title="</style>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg>',
      '<p></p><style><g title="</style>',
    ]);
  });
  QUnit.test('Avoid mXSS in Chrome 77 and above using HTML', function (assert) {
    var clean = DOMPurify.sanitize('<svg></p><title><a href="</title>qqq');
    assert.contains(clean, [
      '',
      '<svg><p></p><title></title></svg>',
      '<svg></svg><p></p><title>&lt;a href="</title>qqq<img src="">"&gt;',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><title /></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><style /></svg>',
      '<svg></svg><p></p><title>&lt;a href="</title>qqq',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p><title /></svg></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><p></p></svg>',
      '<p></p><title>&lt;a href="</title>qqq',
    ]);
  });

  /* Helpers for the nesting depth tests below */
  var nestedMarkup = function (tag, depth, inner) {
    return (
      new Array(depth + 1).join('<' + tag + '>') +
      inner +
      new Array(depth + 1).join('</' + tag + '>')
    );
  };

  var countTags = function (html, tag) {
    return html.split('<' + tag + '>').length - 1;
  };

  QUnit.test('Test nesting depth limit inside template content', function (
    assert
  ) {
    var clean = DOMPurify.sanitize(
      '<p><template>' + nestedMarkup('div', 300, '<img>') + '</template></p>'
    );
    var depth = countTags(clean, 'div');
    assert.ok(depth < 255, 'Nesting depth is limited, got ' + depth);
    assert.ok(depth > 200, 'Moderate nesting is kept, got ' + depth);
    assert.equal(clean.indexOf('<img'), -1, 'Deeply nested <img> is removed');
  });
  QUnit.test(
    'Test nesting depth limit inside template content with clobbered parentNode',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<p><template>' +
          nestedMarkup(
            'div',
            200,
            '<form><input name="parentNode">' +
              nestedMarkup('div', 100, '<img>') +
              '</form>'
          ) +
          '</template></p>'
      );
      var depth = countTags(clean, 'div');
      assert.ok(depth < 255, 'Nesting depth is limited, got ' + depth);
      assert.ok(depth > 200, 'Moderate nesting is kept, got ' + depth);
      assert.equal(
        clean.indexOf('<img'),
        -1,
        'Deeply nested <img> is removed'
      );
    }
  );
  QUnit.test(
    'Test nesting depth limit inside template content with clobbered __removalCount',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<p><template><div><form><input name="__removalCount">' +
          nestedMarkup('div', 300, '<img>') +
          '</form></div></template></p>'
      );
      var depth = countTags(clean, 'div');
      assert.ok(depth < 255, 'Nesting depth is limited, got ' + depth);
      assert.equal(
        clean.indexOf('<img'),
        -1,
        'Deeply nested <img> is removed'
      );
    }
  );
  QUnit.test(
    'Test nesting depth limit inside template content against prototype pollution',
    function (assert) {
      var dirty =
        '<p><template>' + nestedMarkup('div', 300, '<img>') + '</template></p>';
      var pollutions = [
        ['__depth', 'x'],
        ['__depth', -1000],
        ['__removalCount', -1],
        ['__removalCount', 'x'],
        [
          '__removalCount',
          {
            valueOf: function () {
              return NaN;
            },
          },
        ],
      ];
      pollutions.forEach(function (pollution) {
        var clean;
        var label =
          'Object.prototype.' + pollution[0] + ' = ' + String(pollution[1]);
        Object.prototype[pollution[0]] = pollution[1];
        try {
          clean = DOMPurify.sanitize(dirty);
        } finally {
          delete Object.prototype[pollution[0]];
        }

        var depth = countTags(clean, 'div');
        assert.ok(depth < 255, label + ': nesting depth is limited, got ' + depth);
        assert.equal(
          clean.indexOf('<img'),
          -1,
          label + ': deeply nested <img> is removed'
        );
      });
    }
  );
  QUnit.test('Test nesting depth limit with clobbered parentNode', function (
    assert
  ) {
    var clean = DOMPurify.sanitize(
      nestedMarkup(
        'div',
        200,
        '<form><input name="parentNode">' +
          nestedMarkup('div', 100, '<img>') +
          '</form>'
      )
    );
    var depth = countTags(clean, 'div');
    assert.ok(depth < 255, 'Nesting depth is limited, got ' + depth);
    assert.ok(depth > 200, 'Moderate nesting is kept, got ' + depth);
    assert.equal(clean.indexOf('<img'), -1, 'Deeply nested <img> is removed');
  });
  QUnit.test(
    'Test nesting depth limit with WHOLE_DOCUMENT and clobbered document',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<img name="__depth">' + nestedMarkup('div', 300, '<img src="x">'),
        { WHOLE_DOCUMENT: true }
      );
      var depth = countTags(clean, 'div');
      assert.ok(depth < 255, 'Nesting depth is limited, got ' + depth);
      assert.equal(
        clean.indexOf('<img src'),
        -1,
        'Deeply nested <img> is removed'
      );
    }
  );
  QUnit.test('Test nesting depth limit counts removed elements', function (
    assert
  ) {
    var clean = DOMPurify.sanitize(
      nestedMarkup('r', 200, nestedMarkup('div', 100, '<img>'))
    );
    var depth = countTags(clean, 'div');
    assert.ok(depth < 100, 'Removed ancestors are counted, got ' + depth);
    assert.equal(clean.indexOf('<img'), -1, 'Deeply nested <img> is removed');
  });
  QUnit.test(
    'Test nesting depth limit against prototype pollution',
    function (assert) {
      var dirty = nestedMarkup('div', 300, '<img>');
      var pollutions = [
        ['__depth', 'x'],
        ['__depth', -1000],
        ['__removalCount', -1],
        ['__removalCount', -1000],
        ['__removalCount', 'x'],
      ];
      pollutions.forEach(function (pollution) {
        var clean;
        var label =
          'Object.prototype.' + pollution[0] + ' = ' + String(pollution[1]);
        Object.prototype[pollution[0]] = pollution[1];
        try {
          clean = DOMPurify.sanitize(dirty);
        } finally {
          delete Object.prototype[pollution[0]];
        }

        var depth = countTags(clean, 'div');
        assert.ok(depth < 255, label + ': nesting depth is limited, got ' + depth);
        assert.equal(
          clean.indexOf('<img'),
          -1,
          label + ': deeply nested <img> is removed'
        );
      });
    }
  );
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is true',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
        RETURN_TRUSTED_TYPE: true,
      });
      var type = typeof clean;
      assert.contains(type, ['TrustedHTML', 'string', 'object']);
    }
  );
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is false',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
        RETURN_TRUSTED_TYPE: false,
      });
      var type = typeof clean;
      assert.equal(type, 'string');
    }
  );
  QUnit.test(
    'Test for correct return value when RETURN_TRUSTED_TYPE is not set',
    function (assert) {
      var clean = DOMPurify.sanitize('<b>hello goodbye</b>');
      var type = typeof clean;
      assert.equal(type, 'string');
    }
  );
  QUnit.test(
    'Test for DoS coming from table sanitization 1/2 See #365',
    function (assert) {
      var config = { FORBID_TAGS: ['tbody'] };
      var clean = DOMPurify.sanitize(
        '<table><tbody><tr><td>test</td></tr></tbody></table>',
        config
      );
      assert.equal(
        clean,
        '<table><tbody><tr><td>test</td></tr></tbody></table>'
      );
    }
  );
  QUnit.test(
    'Test for DoS coming from table sanitization 2/2 See #365',
    function (assert) {
      var config = {
        ALLOWED_TAGS: [
          'b',
          'strong',
          'i',
          'italic',
          'div',
          'p',
          'span',
          'ul',
          'li',
          'ol',
          'a',
          'img',
          'br',
          'tr',
          'td',
          'th',
          'table',
          'h1',
          'h2',
          'h3',
          'h4',
          'h5',
          'h6',
        ],
        ALLOW_DATA_ATTR: false,
        ALLOWED_ATTR: ['src', 'class', 'target', 'href'],
      };
      var clean = DOMPurify.sanitize(
        '<table><colgroup><col></col></colgroup><tbody><tr><td >test</td></tr></tbody></table>',
        config
      );
      assert.equal(
        clean,
        '<table><tbody><tr><td>test</td></tr></tbody></table>'
      );
    }
  );
  QUnit.test('Test for less agressive mXSS handling, See #369', function (
    assert
  ) {
    var config = {
      FORBID_TAGS: ['svg', 'math'],
    };
    var clean = DOMPurify.sanitize(
      '<b data-test="<span>content</span>"></b>',
      config
    );
    assert.contains(clean, [
      '<b data-test="<span>content</span>"></b>',
      '<b data-test="&lt;span&gt;content&lt;/span&gt;"></b>',
    ]);
  });
  QUnit.test(
    'Test against mXSS using text integration points and removal 1/2',
    function (assert) {
      var config = {
        FORBID_TAGS: ['mi'],
      };
      var clean = DOMPurify.sanitize(
        '<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',
        config
      );
      assert.contains(clean, [
        '<math><b><style><b title="</style></b></math>',
        '<math></math>',
      ]);
    }
  );
  QUnit.test(
    'Test against mXSS using text integration points and removal 2/2',
    function (assert) {
      var config = {
        ADD_TAGS: ['xmp'],
      };
      var clean = DOMPurify.sanitize(
        "x<noframes><svg><b><xmp><b title='</xmp><img>",
        config
      );
      assert.contains(clean, ['x']);
    }
  );
  QUnit.test(
    'Test against insecure behavior in jQUery v3.0 and newer 1/2',
    function (assert) {
      var config = {
        SAFE_FOR_JQUERY: true,
      };
      var clean = DOMPurify.sanitize(
        '<img x="/><img src=x onerror=alert(1)>" y="<x">',
        config
      );
      assert.contains(clean, [
        '<img y="<x" x="/><img src=x onerror=alert(1)>">', // jsdom
        '<img y="<x">',
        '<img y="&lt;x">',
        '<img y="<x">',
      ]);
    }
  );
  QUnit.test(
    'Test against insecure behavior in jQUery v3.0 and newer 2/2',
    function (assert) {
      var config = {
        SAFE_FOR_JQUERY: true,
        ADD_TAGS: ['noscript'],
      };
      var clean = DOMPurify.sanitize(
        "a<noscript><p id='><noscript /><img src=x onerror=alert(1)>'></noscript>",
        config
      );
      assert.contains(clean, [
        "a<noscript>&lt;p id='>&lt;noscript />&lt;img src=x onerror=alert(1)>'></noscript>", // jsdom
        'a<noscript><p></p></noscript>',
      ]);
    }
  );
  QUnit.test(
    'Test against data URIs in anchors without proper config flag',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<a href="data:image/gif;base64,123">icon.gif</a>'
      );
      assert.equal(clean, '<a>icon.gif</a>');
    }
  );
  QUnit.test(
    'Test against data URIs in anchors using proper config flag',
    function (assert) {
      var clean = DOMPurify.sanitize(
        '<a href="data:image/gif;base64,123">icon.gif</a>',
        {
          ADD_DATA_URI_TAGS: ['a', 'b'],
        }
      );
      assert.equal(clean, '<a href="data:image/gif;base64,123">icon.gif</a>');
    }
  );
  QUnit.test(
    'Test against nesting-based mXSS via form and table namespace confusion',
    function (assert) {
      var payloads = [
        '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>',
        '<math><mtext><table><mglyph><style></math><img src onerror=alert(1)>',
      ];
      payloads.forEach(function (payload) {
        var clean = DOMPurify.sanitize(payload);
        /* Re-parse the sanitized markup in an inert document (sink roundtrip) */
        var doc = document.implementation.createHTMLDocument('');
        doc.body.innerHTML = clean;
        assert.equal(
          clean.indexOf('<math'),
          -1,
          'math with nested form/table is removed: ' + clean
        );
        assert.equal(
          doc.body.querySelectorAll('img').length,
          0,
          'no <img> is created after the serialize-parse roundtrip: ' + clean
        );
      });
    }
  );
  /* GHSA-r47g-fvhr-h676: a clobbered IN_PLACE root can not be detached by
     _forceRemove when it has no parent, and the main loop then never
     sanitizes its attributes. sanitize() must refuse such a root. */
  var supportsFormClobbering = function () {
    var form = document.createElement('form');
    var input = document.createElement('input');
    input.setAttribute('name', 'nodeName');
    form.appendChild(input);
    return typeof form.nodeName !== 'string';
  };
  /* Clobber form[name] with a named child. Engines without form named
     properties (e.g. jsdom) get the same shadowing simulated through an
     own property, so the clobbering checks are exercised everywhere. */
  var clobberForm = function (form, name, tag) {
    var child = document.createElement(tag || 'input');
    child.setAttribute('name', name);
    form.appendChild(child);
    if (form[name] !== child) {
      Object.defineProperty(form, name, { value: child, configurable: true });
    }

    return form;
  };
  var createForm = function (attributes) {
    var form = document.createElement('form');
    Object.keys(attributes).forEach(function (attr) {
      form.setAttribute(attr, attributes[attr]);
    });
    return form;
  };
  var inPlaceError = function (root, cfg) {
    var config = cfg || {};
    config.IN_PLACE = true;
    try {
      DOMPurify.sanitize(root, config);
    } catch (error) {
      return String(error && error.message);
    }

    return null;
  };
  QUnit.test(
    'IN_PLACE: parent-less form root clobbered by name="nodeName" throws instead of keeping onmouseover',
    function (assert) {
      if (!supportsFormClobbering()) {
        assert.ok(true, 'SKIP: no form clobbering in this engine');
        return;
      }

      // The advisory's PoC, using real named-property clobbering
      var root = document.createElement('form');
      root.setAttribute('onmouseover', 'window.__rooted_h676 = 1');
      var clobber = document.createElement('input');
      clobber.setAttribute('name', 'nodeName');
      root.appendChild(clobber);
      var message = inPlaceError(root);
      assert.ok(
        /clobbered/.test(message || ''),
        'clobbered parent-less IN_PLACE root must throw, got: ' +
          message +
          ', onmouseover kept: ' +
          root.hasAttribute('onmouseover')
      );
    }
  );
  QUnit.test(
    'IN_PLACE: every clobbering name from GHSA-r47g-fvhr-h676 makes the form root throw',
    function (assert) {
      var clobberNames = [
        'nodeName',
        'setAttribute',
        'namespaceURI',
        'insertBefore',
        'hasChildNodes',
        'childNodes',
        'attributes',
        'textContent',
        'removeChild',
        'removeAttribute',
      ];
      clobberNames.forEach(function (name) {
        var root = clobberForm(
          createForm({ onmouseover: 'window.__rooted_' + name + ' = 1' }),
          name
        );
        var message = inPlaceError(root);
        assert.ok(
          /clobbered/.test(message || ''),
          'IN_PLACE root clobbered by name="' +
            name +
            '" must throw, got: ' +
            message
        );
      });
      var root = clobberForm(
        createForm({ onmouseover: 'window.__rooted_select = 1' }),
        'childNodes',
        'select'
      );
      var message = inPlaceError(root);
      assert.ok(
        /clobbered/.test(message || ''),
        'IN_PLACE root clobbered by <select name="childNodes"> must throw, got: ' +
          message
      );
    }
  );
  QUnit.test(
    'IN_PLACE: clobbered form root with javascript: action, clobbering id or template expressions throws',
    function (assert) {
      var cases = [
        ['action', { action: 'javascript:alert(1)' }, {}],
        ['formaction', { formaction: 'javascript:alert(1)' }, {}],
        ['id', { id: 'cookie' }, {}],
        [
          'SAFE_FOR_TEMPLATES',
          { title: "{{constructor.constructor('alert(1)')()}}" },
          { SAFE_FOR_TEMPLATES: true },
        ],
      ];
      cases.forEach(function (testCase) {
        var root = clobberForm(createForm(testCase[1]), 'nodeName');
        var message = inPlaceError(root, testCase[2]);
        assert.ok(
          /clobbered/.test(message || ''),
          testCase[0] + ': clobbered IN_PLACE root must throw, got: ' + message
        );
        // The named-property mapping is sticky, a second call must throw too
        message = inPlaceError(root, testCase[2]);
        assert.ok(
          /clobbered/.test(message || ''),
          testCase[0] + ': second sanitize() call must throw, got: ' + message
        );
      });
    }
  );
  QUnit.test(
    'IN_PLACE: clobbered form root is rejected even when it has a parent',
    function (assert) {
      var wrapper = document.createElement('div');
      var root = clobberForm(
        createForm({ onmouseover: 'window.__rooted_parented = 1' }),
        'nodeName'
      );
      wrapper.appendChild(root);
      var message = inPlaceError(root);
      assert.ok(
        /clobbered/.test(message || ''),
        'clobbered IN_PLACE root with a parent must throw, got: ' + message
      );
      assert.equal(
        wrapper.querySelectorAll('form').length,
        1,
        'the root is left untouched when sanitize() throws'
      );
    }
  );
  QUnit.test(
    'IN_PLACE: form root clobbering nodeType throws instead of being stringified',
    function (assert) {
      // A clobbered nodeType used to fail the node check, so the root was
      // stringified and the caller's node was never sanitized at all. The
      // nodeType probe in _isClobbered flags such a root, so sanitize()
      // refuses it like every other clobbered IN_PLACE root (CVE-2026-65902)
      var root = clobberForm(
        createForm({
          onmouseover: 'window.__rooted_nodetype = 1',
          action: 'javascript:alert(1)',
        }),
        'nodeType'
      );
      var message = inPlaceError(root);
      assert.ok(
        /clobbered/.test(message || ''),
        'IN_PLACE root clobbered by name="nodeType" must throw, got: ' +
          message
      );
    }
  );
  QUnit.test(
    'IN_PLACE: polluted Object.prototype.__depth makes the root throw instead of returning it unsanitized',
    function (assert) {
      var pollutions = [
        ['__depth', 'x'],
        ['__removalCount', 'x'],
      ];
      pollutions.forEach(function (pollution) {
        var root = document.createElement('a');
        root.setAttribute('href', 'javascript:alert(1)');
        root.setAttribute('onmouseover', 'window.__rooted_polluted = 1');
        var message;
        Object.prototype[pollution[0]] = pollution[1];
        try {
          message = inPlaceError(root);
        } finally {
          delete Object.prototype[pollution[0]];
        }

        assert.ok(
          /clobbered/.test(message || ''),
          'Object.prototype.' +
            pollution[0] +
            ': IN_PLACE root must throw, got: ' +
            message +
            ', onmouseover kept: ' +
            root.hasAttribute('onmouseover')
        );
      });
    }
  );
  QUnit.test(
    'IN_PLACE: clobbered forms below the root are removed, unclobbered roots are still sanitized',
    function (assert) {
      // A clobbered form with a parent is removed by the main loop
      var wrapper = document.createElement('div');
      wrapper.appendChild(
        clobberForm(
          createForm({ onmouseover: 'window.__rooted_nested = 1' }),
          'childNodes',
          'select'
        )
      );
      wrapper.appendChild(
        clobberForm(
          createForm({ onmouseover: 'window.__rooted_nested = 2' }),
          'nodeName'
        )
      );
      assert.equal(inPlaceError(wrapper), null, 'wrapper root does not throw');
      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'clobbered forms below the root are removed: ' + wrapper.innerHTML
      );
      // A document fragment root is not an element and does not throw
      var fragment = document.createDocumentFragment();
      fragment.appendChild(
        clobberForm(
          createForm({ onmouseover: 'window.__rooted_fragment = 1' }),
          'nodeName'
        )
      );
      assert.equal(inPlaceError(fragment), null, 'fragment root does not throw');
      assert.equal(
        fragment.firstChild,
        null,
        'clobbered form inside a fragment root is removed'
      );
      // An unclobbered form root is sanitized as before
      var plain = createForm({
        onmouseover: 'window.__rooted_plain = 1',
        action: 'javascript:alert(1)',
      });
      plain.appendChild(document.createElement('input'));
      assert.equal(inPlaceError(plain), null, 'unclobbered root does not throw');
      assert.equal(plain.hasAttribute('onmouseover'), false, 'onmouseover removed');
      assert.equal(plain.hasAttribute('action'), false, 'javascript: action removed');
      assert.equal(plain.querySelectorAll('input').length, 1, 'input is kept');
    }
  );
  /* GHSA-hpcv-96wg-7vj8: nodes of a foreign realm (e.g. a same-origin
     iframe document) handed to DOMPurify with IN_PLACE. Realm-bound
     `instanceof` checks against the instance's own constructors
     short-circuited to false for them and silently skipped sanitization:
     the root kept its event handlers, clobbered form roots were not refused
     and <template>.content was never walked. */
  /* A DOMPurify instance whose constructors are not on the prototype chain
     of this document's nodes, which is exactly what an instance sees for
     nodes of a foreign realm. The constructors' prototypes still reach the
     real prototype getters, as the getters of one realm work on the nodes
     of any realm. This reproduces the realm mismatch in every engine, also
     where iframes share the parent's constructors (jsdom) or where
     `instanceof` on DOM interfaces is cross-realm aware (Gecko). */
  var createRealmBoundPurify = function () {
    var view = {
      document: document,
      HTMLTemplateElement: window.HTMLTemplateElement,
      NodeFilter: window.NodeFilter,
      DOMParser: window.DOMParser,
    };
    [
      'Node',
      'Element',
      'DocumentFragment',
      'NamedNodeMap',
      'Text',
      'Comment',
    ].forEach(function (name) {
      if (window[name] && window[name].prototype) {
        var ForeignRealmConstructor = function () {};
        ForeignRealmConstructor.prototype = Object.create(
          window[name].prototype
        );
        view[name] = ForeignRealmConstructor;
      }
    });
    return DOMPurify(view);
  };
  /* Run a scenario against every available foreign realm: the realm-bound
     instance above on this document's nodes, and this instance on the nodes
     of a same-origin iframe document when the engine can provide one. */
  var forEachForeignRealm = function (callback) {
    var realmBoundPurify = createRealmBoundPurify();
    callback(realmBoundPurify, document, 'realm-bound instance');

    var iframe = null;
    var foreignDoc = null;
    try {
      iframe = document.createElement('iframe');
      iframe.srcdoc = '<!doctype html><html><body></body></html>';
      document.body.appendChild(iframe);
      foreignDoc = iframe.contentDocument;
    } catch (_) {
      foreignDoc = null;
    }

    if (!foreignDoc || typeof foreignDoc.createElement !== 'function') {
      if (iframe && iframe.parentNode) {
        iframe.parentNode.removeChild(iframe);
      }

      return;
    }

    try {
      callback(DOMPurify, foreignDoc, 'iframe document');
    } finally {
      iframe.parentNode.removeChild(iframe);
    }
  };
  /* Clobber form[name] with a named child of the form's own realm. Engines
     without form named properties get the shadowing simulated through an
     own property, like clobberForm() above. */
  var clobberForeignForm = function (form, name) {
    var child = form.ownerDocument.createElement('input');
    child.setAttribute('name', name);
    form.appendChild(child);
    if (form[name] !== child) {
      Object.defineProperty(form, name, { value: child, configurable: true });
    }

    return form;
  };
  QUnit.test(
    'GHSA-hpcv-96wg-7vj8: IN_PLACE root of a foreign realm and its children are sanitized',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        var root = doc.createElement('div');
        root.setAttribute('onmouseover', 'window.__hpcv_root_xss = 1');
        var link = doc.createElement('a');
        link.setAttribute('href', 'javascript:alert(1)');
        link.setAttribute('onclick', 'window.__hpcv_child_xss = 1');
        link.appendChild(doc.createTextNode('safe'));
        root.appendChild(link);
        root.appendChild(doc.createTextNode(' text'));
        root.appendChild(doc.createComment('note'));
        var script = doc.createElement('script');
        script.textContent = 'window.__hpcv_script_xss = 1';
        root.appendChild(script);

        var clean = purify.sanitize(root, { IN_PLACE: true });
        assert.strictEqual(
          clean,
          root,
          realm + ': the root node itself is returned'
        );
        assert.equal(
          root.hasAttribute('onmouseover'),
          false,
          realm + ': onmouseover is removed from the foreign-realm root'
        );
        assert.equal(
          root.querySelectorAll('script').length,
          0,
          realm + ': foreign-realm script child is removed'
        );
        var kept = root.querySelector('a');
        assert.ok(kept, realm + ': allowed foreign-realm child element is kept');
        assert.equal(
          kept && kept.hasAttribute('onclick'),
          false,
          realm + ': onclick is removed from the foreign-realm child'
        );
        assert.equal(
          kept && kept.hasAttribute('href'),
          false,
          realm + ': javascript: href is removed from the foreign-realm child'
        );
        assert.equal(
          root.textContent,
          'safe text',
          realm + ': foreign-realm text nodes are kept'
        );
      });
    }
  );
  QUnit.test(
    'GHSA-hpcv-96wg-7vj8: clobbered form root of a foreign realm throws on IN_PLACE',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        ['attributes', 'nodeName', 'childNodes'].forEach(function (name) {
          var form = doc.createElement('form');
          form.setAttribute('onmouseover', 'window.__hpcv_form_xss = 1');
          form.setAttribute('action', 'javascript:alert(1)');
          clobberForeignForm(form, name);
          var message = null;
          try {
            purify.sanitize(form, { IN_PLACE: true });
          } catch (error) {
            message = String(error && error.message);
          }

          assert.ok(
            /clobbered/.test(message || ''),
            realm +
              ': foreign-realm form root clobbered by name="' +
              name +
              '" must throw, got: ' +
              message +
              ', onmouseover kept: ' +
              form.hasAttribute('onmouseover')
          );
        });

        // The advisory's PoC: a clobbered form below a foreign-realm root
        var wrapper = doc.createElement('div');
        var nested = doc.createElement('form');
        nested.setAttribute('onmouseover', 'window.__hpcv_nested_xss = 1');
        clobberForeignForm(nested, 'attributes');
        wrapper.appendChild(nested);
        purify.sanitize(wrapper, { IN_PLACE: true });
        var forms = wrapper.querySelectorAll('form');
        assert.ok(
          forms.length === 0 || !forms[0].hasAttribute('onmouseover'),
          realm +
            ': clobbered foreign-realm form keeps no onmouseover: ' +
            wrapper.innerHTML
        );
      });
    }
  );
  QUnit.test(
    'GHSA-hpcv-96wg-7vj8: foreign-realm form root clobbering nodeType throws on IN_PLACE',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        // A clobbered nodeType used to fail the realm-bound node check, so
        // the root was stringified and the caller's node never sanitized.
        // The nodeType probe in _isClobbered now refuses such a root, also
        // for nodes of a foreign realm (CVE-2026-65902)
        var root = clobberForeignForm(doc.createElement('form'), 'nodeType');
        root.setAttribute('onmouseover', 'window.__hpcv_nodetype_xss = 1');
        root.setAttribute('action', 'javascript:alert(1)');
        var message = null;
        try {
          purify.sanitize(root, { IN_PLACE: true });
        } catch (error) {
          message = String(error && error.message);
        }

        assert.ok(
          /clobbered/.test(message || ''),
          realm +
            ': foreign-realm form root clobbered by name="nodeType" must throw, got: ' +
            message
        );
      });
    }
  );
  QUnit.test(
    'GHSA-hpcv-96wg-7vj8: foreign-realm <template>.content is walked and sanitized',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        var wrapper = doc.createElement('div');
        var tpl = doc.createElement('template');
        if (!tpl.content || typeof tpl.content.querySelector !== 'function') {
          assert.ok(true, realm + ': SKIP: no template content support');
          return;
        }

        tpl.innerHTML = '<img src="x" onerror="window.__hpcv_tpl_xss = 1">';
        if (!tpl.content.querySelector('img')) {
          // The innerHTML setter does not target the template contents in
          // this engine, build them through the inert contents document
          while (tpl.firstChild) {
            tpl.removeChild(tpl.firstChild);
          }

          var inertImg = tpl.content.ownerDocument.createElement('img');
          inertImg.setAttribute('src', 'x');
          inertImg.setAttribute('onerror', 'window.__hpcv_tpl_xss = 1');
          tpl.content.appendChild(inertImg);
        }

        wrapper.appendChild(tpl);
        purify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(
          wrapper.querySelectorAll('template').length,
          1,
          realm + ': the foreign-realm template is kept'
        );
        var img = tpl.content.querySelector('img');
        assert.ok(img, realm + ': template content was reached');
        assert.equal(
          img && img.getAttribute('onerror'),
          null,
          realm + ': onerror inside foreign-realm <template> must be stripped'
        );
      });
    }
  );
  QUnit.test(
    'GHSA-hpcv-96wg-7vj8: foreign-realm element with a forbidden namespace is removed',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        var wrapper = doc.createElement('div');
        var weird = doc.createElementNS('urn:example:not-allowed', 'weird');
        weird.setAttribute('onclick', 'window.__hpcv_ns_xss = 1');
        wrapper.appendChild(weird);

        purify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(
          wrapper.getElementsByTagName('weird').length,
          0,
          realm + ': foreign-realm bad-namespace element must be removed'
        );
      });
    }
  );
  /* CVE-2026-65902: a form clobbering nodeType through a named descendant
     (e.g. <input name="nodeType">) passed _isClobbered, while the walk reads
     currentNode.nodeType directly to set the nesting depth. The clobbered
     form never got a depth, so the counter restarted below it and deeply
     nested markup slipped past MAX_NESTING_DEPTH. _isClobbered now compares
     the direct read against the cached Node.prototype getter. */
  var supportsNodeTypeClobbering = function () {
    var form = document.createElement('form');
    var input = document.createElement('input');
    input.setAttribute('name', 'nodeType');
    form.appendChild(input);
    return typeof form.nodeType !== 'number';
  };
  QUnit.test(
    'CVE-2026-65902: form clobbering nodeType below the root is removed',
    function (assert) {
      var wrapper = document.createElement('div');
      wrapper.appendChild(
        clobberForm(
          createForm({ onmouseover: 'window.__nodetype_nested = 1' }),
          'nodeType'
        )
      );
      assert.equal(inPlaceError(wrapper), null, 'wrapper root does not throw');
      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'form clobbering nodeType is removed: ' + wrapper.innerHTML
      );
      // An unclobbered form is still kept
      var plain = document.createElement('div');
      var form = createForm({ onmouseover: 'window.__nodetype_plain = 1' });
      form.appendChild(document.createElement('input'));
      plain.appendChild(form);
      assert.equal(inPlaceError(plain), null, 'plain root does not throw');
      assert.equal(
        plain.innerHTML,
        '<form><input></form>',
        'unclobbered form is kept and sanitized'
      );
    }
  );
  QUnit.test(
    'CVE-2026-65902: form clobbering nodeType can not reset the nesting depth counter',
    function (assert) {
      // wrapper > 200 x div > form[nodeType clobbered] > 200 x div > img
      var wrapper = document.createElement('div');
      var parent = wrapper;
      var i;
      var next;
      for (i = 0; i < 200; i++) {
        next = document.createElement('div');
        parent.appendChild(next);
        parent = next;
      }

      var form = clobberForm(document.createElement('form'), 'nodeType');
      parent.appendChild(form);
      parent = form;
      for (i = 0; i < 200; i++) {
        next = document.createElement('div');
        parent.appendChild(next);
        parent = next;
      }

      var img = document.createElement('img');
      img.setAttribute('src', 'x');
      parent.appendChild(img);

      DOMPurify.sanitize(wrapper, { IN_PLACE: true });

      var kept = wrapper.querySelector('img');
      var depth = 0;
      var node = kept;
      while (node && node !== wrapper) {
        depth++;
        node = node.parentNode;
      }

      assert.ok(
        !kept || depth < 255,
        'no element survives nested deeper than the limit, <img> depth: ' +
          depth
      );
      assert.equal(
        wrapper.querySelectorAll('form').length,
        0,
        'form clobbering nodeType is removed'
      );
    }
  );
  QUnit.test(
    'CVE-2026-65902: string input with a form clobbering nodeType',
    function (assert) {
      var dirty =
        '<form onsubmit="alert(1)"><input onfocus="alert(2)" name="nodeType">x</form>';
      var clean = DOMPurify.sanitize(dirty);
      if (supportsNodeTypeClobbering()) {
        // Real named-property clobbering, the form must be removed
        assert.equal(clean, '', 'form clobbering nodeType is removed');
      } else {
        // No form named properties in this engine (e.g. jsdom), nothing is
        // clobbered and only the event handlers and the name are dropped
        assert.equal(clean, '<form><input>x</form>', 'form is sanitized');
      }
    }
  );

  /* CVE-2026-65902: hook-driven allowlist pollution. The data.allowedTags /
     data.allowedAttributes fields handed to uponSanitizeElement /
     uponSanitizeAttribute hooks are references to the live ALLOWED_TAGS /
     ALLOWED_ATTR sets, which are the module-level defaults when no explicit
     ALLOWED_TAGS / ALLOWED_ATTR is configured. A hook writing
     data.allowedTags.script = true must not widen the defaults of later
     calls, even after removeAllHooks() and clearConfig(). The sets are
     cloned per sanitize() call whenever such a hook is registered, so the
     documented in-call widening keeps working. Each test uses a fresh
     instance, as the bug under test is cross-call pollution. */
  var withFreshPurify = function (callback) {
    var purify = DOMPurify(window);
    try {
      callback(purify);
    } finally {
      purify.removeAllHooks();
      purify.clearConfig();
    }
  };
  QUnit.test(
    'CVE-2026-65902: baseline, <script> and onclick are stripped under default config',
    function (assert) {
      withFreshPurify(function (purify) {
        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'fresh default sanitize strips <script>'
        );
        assert.equal(
          purify.sanitize('<a onclick="alert(1)">x</a>'),
          '<a>x</a>',
          'fresh default sanitize strips onclick'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: in-call widening via hook still works',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          if (data.tagName === 'is-custom') {
            data.allowedTags['is-custom'] = true;
          }
        });
        purify.addHook('uponSanitizeAttribute', function (node, data) {
          if (data.attrName === 'super-custom') {
            data.allowedAttributes['super-custom'] = true;
          }
        });

        var input = '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
        assert.equal(
          purify.sanitize(input),
          input,
          'guarded hook widens allowlist for matching element in-call'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: unguarded element hook does not poison subsequent default-config calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          // The leaky pattern: unconditionally widen
          data.allowedTags.script = true;
        });

        assert.equal(
          purify.sanitize('<svg><script>1</script></svg>'),
          '<svg><script>1</script></svg>',
          'in-call widening still works while hook is registered'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'default sanitize after element-hook removal strips <script>'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: unguarded attribute hook does not poison subsequent default-config calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeAttribute', function (node, data) {
          data.allowedAttributes.onclick = true;
        });

        assert.ok(
          purify.sanitize('<a onclick="alert(1)">x</a>').indexOf('onclick') !==
            -1,
          'in-call widening still works for attribute hook'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<a onclick="alert(1)">x</a>'),
          '<a>x</a>',
          'default sanitize after attr-hook removal strips onclick'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: pollution does not cross instance boundaries',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
        });
        purify.sanitize('<svg><script>alert(1)</script></svg>');

        var freshInstance = DOMPurify(window);
        assert.equal(
          freshInstance.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'fresh DOMPurify instance must not inherit poisoned defaults'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: read-only hook does not poison defaults',
    function (assert) {
      withFreshPurify(function (purify) {
        var sawScriptKey;
        purify.addHook('uponSanitizeElement', function (node, data) {
          if (sawScriptKey === undefined) {
            sawScriptKey = 'script' in data.allowedTags;
          }
        });

        purify.sanitize('<div><span>hi</span></div>');

        assert.strictEqual(
          sawScriptKey,
          false,
          'hook sees default allowlist with script NOT included'
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'read-only hook does not poison defaults'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: multiple polluting calls do not accumulate state in defaults',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
          data.allowedTags.iframe = true;
          data.allowedTags.object = true;
        });

        for (var i = 0; i < 10; i++) {
          purify.sanitize('<div></div>');
        }

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>1</script></svg>'),
          '<svg></svg>',
          'script still stripped after 10 polluting calls'
        );
        assert.equal(
          purify.sanitize('<iframe src="x"></iframe>'),
          '',
          'iframe still stripped after 10 polluting calls'
        );
        assert.equal(
          purify.sanitize('<object data="x"></object>'),
          '',
          'object still stripped after 10 polluting calls'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-65902: explicit cfg.ALLOWED_TAGS path is unaffected by hook mutation in other calls',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node, data) {
          data.allowedTags.script = true;
        });

        var withCfg = purify.sanitize('<svg><script>alert(1)</script></svg>', {
          ALLOWED_TAGS: ['svg'],
        });
        assert.ok(
          withCfg.indexOf('<script>') !== -1,
          'explicit-cfg call respects in-call hook widening: ' + withCfg
        );

        purify.removeAllHooks();
        purify.clearConfig();

        assert.equal(
          purify.sanitize('<svg><script>alert(1)</script></svg>'),
          '<svg></svg>',
          'default-cfg call after explicit-cfg+hook is unaffected'
        );
      });
    }
  );

  /* CVE-2026-49978: an attached shadow root nested inside <template>.content
     was reached by no walk. The NodeIterator does not enter shadow trees and
     the template content recursion never inspected shadowRoot, so the payload
     of such a shadow root survived IN_PLACE sanitization and went live once
     the content was stamped into the document (clonable shadow roots are
     copied by cloneNode / importNode). _sanitizeShadowDOM now walks the shadow
     root of every element it iterates. The trees are built inside the inert
     template content, so no image request is made. Engines without
     attachShadow (e.g. jsdom) skip these tests. */
  var supportsShadowRoots = function () {
    var probe = document.createElement('div');
    try {
      probe.attachShadow({ mode: 'open' });
      return true;
    } catch (_) {
      return false;
    }
  };
  var supportsClonableShadowRoots = function () {
    var probe = document.createElement('div');
    try {
      probe.attachShadow({ mode: 'open', clonable: true });
    } catch (_) {
      return false;
    }

    /* Engines predating clonable shadow roots accept the unknown dictionary
       member, but do not copy the shadow root when cloning the host */
    return Boolean(probe.cloneNode(true).shadowRoot);
  };
  QUnit.test(
    'CVE-2026-49978: shadow root inside template.content is sanitized in-place',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        // The shadow root's onerror attribute must be stripped.
        var shadowImg =
          tpl.content.firstChild &&
          tpl.content.firstChild.shadowRoot &&
          tpl.content.firstChild.shadowRoot.querySelector('img');
        if (shadowImg) {
          assert.equal(
            shadowImg.getAttribute('onerror'),
            null,
            'onerror inside shadow root inside template.content must be stripped'
          );
        } else {
          // The whole img may have been removed; also acceptable.
          assert.ok(
            true,
            '<img> removed entirely from shadow root inside template.content'
          );
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root inside template.content does not survive stamping',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported in this engine');
        return;
      }

      withFreshPurify(function (purify) {
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        // The realistic exploitation path: clone the (now-sanitized)
        // template content into the live document. The cloned shadow
        // tree must not carry the onerror.
        var clone = tpl.content.cloneNode(true);
        var clonedImg =
          clone.firstChild &&
          clone.firstChild.shadowRoot &&
          clone.firstChild.shadowRoot.querySelector('img');
        if (clonedImg) {
          assert.equal(
            clonedImg.getAttribute('onerror'),
            null,
            'onerror inside cloned-stamped shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely after stamping');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: nested templates: outer.content > inner.content > shadow root',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Two <template> elements nested by content. The innermost
        // host inside the inner template's content carries the
        // malicious shadow root. Reaches the host only via repeated
        // recursion into template.content.
        var outer = document.createElement('template');
        var inner = document.createElement('template');
        var host = document.createElement('div');
        inner.content.appendChild(host);
        outer.content.appendChild(inner);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(outer, { IN_PLACE: true });

        var sr =
          outer.content.firstChild &&
          outer.content.firstChild.content &&
          outer.content.firstChild.content.firstChild &&
          outer.content.firstChild.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in shadow root inside nested template content must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: wrapper element > template > shadow root: walked via descent',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // A regular <div> as the IN_PLACE root, containing a template,
        // whose content holds a shadow host. The walk must descend
        // through the wrapper, find the template, recurse into
        // template.content, and walk the host's shadow root.
        var root = document.createElement('div');
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        root.appendChild(tpl);
        host.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(root, { IN_PLACE: true });

        var sr =
          root.firstChild &&
          root.firstChild.content &&
          root.firstChild.content.firstChild &&
          root.firstChild.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in shadow root inside template inside wrapper must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: <template> nested inside a shadow root inside template.content is walked',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // template.content > host > shadow root > template > img. The
        // walk alternates between shadow-root descent and
        // template-content recursion.
        var outer = document.createElement('template');
        var host = document.createElement('div');
        outer.content.appendChild(host);
        var sr = host.attachShadow({ mode: 'open' });
        var inner = document.createElement('template');
        inner.innerHTML = '<img src=x onerror=alert(1)>';
        sr.appendChild(inner);

        purify.sanitize(outer, { IN_PLACE: true });

        var innerTpl =
          outer.content.firstChild &&
          outer.content.firstChild.shadowRoot &&
          outer.content.firstChild.shadowRoot.querySelector('template');
        var img = innerTpl && innerTpl.content.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror inside <template>.content inside shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: template.content > shadow root > template > shadow root: alternating descent',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Outer host with shadow root inside template content, whose
        // shadow contains a <template>, whose content contains an inner
        // host with its own shadow root carrying the payload.
        var tpl = document.createElement('template');
        var outerHost = document.createElement('div');
        tpl.content.appendChild(outerHost);
        var outerSr = outerHost.attachShadow({ mode: 'open' });
        var innerTpl = document.createElement('template');
        outerSr.appendChild(innerTpl);
        var innerHost = document.createElement('div');
        innerTpl.content.appendChild(innerHost);
        innerHost.attachShadow({ mode: 'open' }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(tpl, { IN_PLACE: true });

        var outerShadow =
          tpl.content.firstChild && tpl.content.firstChild.shadowRoot;
        var innerSr =
          outerShadow &&
          outerShadow.firstChild &&
          outerShadow.firstChild.content &&
          outerShadow.firstChild.content.firstChild &&
          outerShadow.firstChild.content.firstChild.shadowRoot;
        var img = innerSr && innerSr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in deep shadow > template > shadow chain must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: shadow root nested inside a shadow root inside template.content is walked',
    function (assert) {
      if (!supportsShadowRoots()) {
        assert.ok(true, 'SKIP: attachShadow not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // template.content > host > shadow root > host > shadow root
        var tpl = document.createElement('template');
        var outerHost = document.createElement('div');
        tpl.content.appendChild(outerHost);
        var outerSr = outerHost.attachShadow({ mode: 'open' });
        outerSr.innerHTML = '<b>ok</b><span></span>';
        outerSr.lastChild.attachShadow({ mode: 'open' }).innerHTML =
          '<p>ok</p><img src=x onerror=alert(1)><script>alert(2)</script>';

        purify.sanitize(tpl, { IN_PLACE: true });

        var shadow = tpl.content.firstChild.shadowRoot;
        assert.equal(
          shadow.innerHTML,
          '<b>ok</b><span></span>',
          'benign content of the outer shadow root is kept'
        );
        assert.equal(
          shadow.lastChild.shadowRoot.innerHTML,
          '<p>ok</p><img src="x">',
          'payload of the inner shadow root is sanitized'
        );
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root in nested template survives stamping unscathed',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // End-to-end version of the deeper-nesting case: clonable
        // shadow root inside nested template content, then stamp the
        // outer template into the live document. The cloned tree
        // must not carry the original onerror.
        var outer = document.createElement('template');
        var inner = document.createElement('template');
        var host = document.createElement('div');
        inner.content.appendChild(host);
        outer.content.appendChild(inner);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        purify.sanitize(outer, { IN_PLACE: true });

        // Stamp the outer template into the live document.
        var stamped = outer.content.cloneNode(true);
        var stampedSr =
          stamped.firstChild &&
          stamped.firstChild.content &&
          stamped.firstChild.content.firstChild &&
          stamped.firstChild.content.firstChild.shadowRoot;
        var stampedImg = stampedSr && stampedSr.querySelector('img');
        if (stampedImg) {
          assert.equal(
            stampedImg.getAttribute('onerror'),
            null,
            'stamped img onerror stripped after deep-nested sanitize'
          );
        } else {
          assert.ok(true, '<img> removed entirely after stamping');
        }
      });
    }
  );
  QUnit.test(
    'CVE-2026-49978: clonable shadow root inside template.content of a node input is sanitized',
    function (assert) {
      if (!supportsClonableShadowRoots()) {
        assert.ok(true, 'SKIP: clonable shadow roots not supported');
        return;
      }

      withFreshPurify(function (purify) {
        // Without IN_PLACE the node is imported (cloned) into the
        // sanitization document, which copies the clonable shadow root.
        var root = document.createElement('div');
        var tpl = document.createElement('template');
        var host = document.createElement('div');
        tpl.content.appendChild(host);
        root.appendChild(tpl);
        host.attachShadow({ mode: 'open', clonable: true }).innerHTML =
          '<img src=x onerror=alert(1)>';

        var clean = purify.sanitize(root, { RETURN_DOM: true });

        var cleanTpl = clean.querySelector('template');
        var sr =
          cleanTpl &&
          cleanTpl.content.firstChild &&
          cleanTpl.content.firstChild.shadowRoot;
        var img = sr && sr.querySelector('img');
        if (img) {
          assert.equal(
            img.getAttribute('onerror'),
            null,
            'onerror in the copied shadow root must be stripped'
          );
        } else {
          assert.ok(true, '<img> removed entirely');
        }
      });
    }
  );

  /* GHSA-x4vx-rjvf-j5p4: a live node handed in with IN_PLACE can define an
     own nodeName. The allow/forbid decisions trusted that instance-visible
     property, so a real <script> claiming to be a "DIV" was kept and ran
     once the sanitized tree was inserted into the document, and an <a>
     claiming to be an "IMG" kept a data: URI. The name is now read through
     the cached Node.prototype getter, and a node whose own nodeName diverges
     from it is removed like any other clobbered node. */
  var X4VX_DATA_URI =
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
  var spoofNodeName = function (node, name) {
    Object.defineProperty(node, 'nodeName', {
      value: name,
      configurable: true,
    });
    return node;
  };
  var hasDataHref = function (node) {
    return /^\s*data:/i.test(node.getAttribute('href') || '');
  };
  QUnit.test(
    'GHSA-x4vx-rjvf-j5p4: IN_PLACE removes a <script> child spoofing nodeName as DIV',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var benign = document.createElement('p');
        benign.appendChild(document.createTextNode('ok'));
        host.appendChild(benign);
        var script = document.createElement('script');
        script.textContent = 'window.__x4vx_script = 1';
        host.appendChild(spoofNodeName(script, 'DIV'));

        var clean = purify.sanitize(host, { IN_PLACE: true });

        assert.strictEqual(clean, host, 'the root node itself is returned');
        assert.notEqual(
          script.parentNode,
          host,
          '<script> spoofing nodeName as DIV is removed'
        );
        assert.equal(host.childNodes.length, 1, 'only the benign child is left');
        assert.strictEqual(host.firstChild, benign, 'benign <p> is kept');
      });
    }
  );
  QUnit.test(
    'GHSA-x4vx-rjvf-j5p4: IN_PLACE does not keep a data: href on an <a> spoofing nodeName as IMG',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var link = document.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        link.appendChild(document.createTextNode('click'));
        host.appendChild(spoofNodeName(link, 'IMG'));

        purify.sanitize(host, { IN_PLACE: true });

        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          '<a> spoofing nodeName as IMG is removed or loses its data: href'
        );
      });
    }
  );
  QUnit.test(
    'GHSA-x4vx-rjvf-j5p4: a nodeName getter switching to IMG after the first reads can not keep a data: href',
    function (assert) {
      withFreshPurify(function (purify) {
        var host = document.createElement('div');
        var link = document.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        link.appendChild(document.createTextNode('click'));
        host.appendChild(link);
        /* Consistent while the node is checked for clobbering and its tag
           name is looked up, spoofed for the attribute checks after */
        var reads = 0;
        Object.defineProperty(link, 'nodeName', {
          get: function () {
            reads++;
            return reads <= 2 ? 'A' : 'IMG';
          },
          configurable: true,
        });

        purify.sanitize(host, { IN_PLACE: true });

        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          'data: href is not kept by a nodeName that turns into IMG'
        );
      });
    }
  );
  QUnit.test(
    'GHSA-x4vx-rjvf-j5p4: IN_PLACE root spoofing nodeName is refused',
    function (assert) {
      withFreshPurify(function (purify) {
        var root = document.createElement('script');
        root.textContent = 'window.__x4vx_root = 1';
        spoofNodeName(root, 'DIV');

        var message = null;
        try {
          purify.sanitize(root, { IN_PLACE: true });
        } catch (error) {
          message = String(error && error.message);
        }

        assert.ok(
          message !== null && /clobbered/.test(message),
          'spoofed IN_PLACE root must throw, got: ' + message
        );
      });
    }
  );
  QUnit.test(
    'GHSA-x4vx-rjvf-j5p4: IN_PLACE removes a foreign-realm <script> spoofing nodeName as DIV',
    function (assert) {
      forEachForeignRealm(function (purify, doc, realm) {
        var host = doc.createElement('div');
        var script = doc.createElement('script');
        script.textContent = 'window.__x4vx_foreign = 1';
        host.appendChild(spoofNodeName(script, 'DIV'));
        var link = doc.createElement('a');
        link.setAttribute('href', X4VX_DATA_URI);
        host.appendChild(spoofNodeName(link, 'IMG'));

        purify.sanitize(host, { IN_PLACE: true });

        assert.notEqual(
          script.parentNode,
          host,
          realm + ': <script> spoofing nodeName as DIV is removed'
        );
        assert.ok(
          link.parentNode !== host || !hasDataHref(link),
          realm + ': <a> spoofing nodeName as IMG keeps no data: href'
        );
      });
    }
  );

  // A hook that detaches a node via node.remove() (the documented removal
  // pattern) takes the subtree out of the tree before the walker reaches
  // its descendants - so they are never visited. Without an inline
  // neutralize at the hook-detach early returns, a descendant that was
  // already loading keeps its queued on* handler and fires in page scope
  // after sanitize returns, even though the returned tree is clean.
  // onerror with no src, assert the attribute is gone. Covers both element
  // hooks. (CVE-2026-75838)
  var detachNode = function (node) {
    if (typeof node.remove === 'function') {
      node.remove();
    } else {
      node.parentNode.removeChild(node);
    }
  };
  [
    { hook: 'uponSanitizeElement', label: 'uponSanitizeElement' },
    { hook: 'beforeSanitizeElements', label: 'beforeSanitizeElements' },
  ].forEach(function (testCase) {
    var hook = testCase.hook;
    var label = testCase.label;
    QUnit.test(
      'IN_PLACE: ' +
        label +
        ' node.remove() neutralizes the detached subtree (audit-5 F1)',
      function (assert) {
        var root = document.createElement('div');
        root.innerHTML =
          '<section><img id="tail" onerror="alert(1)"></section>' +
          '<div>safe</div>';
        var tail = root.querySelector('#tail');

        DOMPurify.addHook(hook, function (node) {
          if (node.nodeName === 'SECTION') {
            detachNode(node);
          }
        });

        try {
          var ret = DOMPurify.sanitize(root, { IN_PLACE: true });

          assert.equal(ret, root, 'returns the same in-place node');
          assert.notOk(
            ret.querySelector('section, #tail'),
            'detached subtree is absent from the returned tree'
          );
          assert.strictEqual(
            tail.getAttribute('onerror'),
            null,
            'on* handler stripped from the hook-detached descendant'
          );

          // App-side store-and-rerender must expose no executable sink.
          var probe = document.createElement('div');
          probe.innerHTML = ret.outerHTML + tail.outerHTML;
          assert.notOk(
            probe.querySelector('[onerror],[onload],script'),
            'no executable sink survives serialize/reparse: ' + probe.innerHTML
          );
        } finally {
          DOMPurify.removeHook(hook);
        }
      }
    );
  });

  /* CVE-2026-75838 variants: every way a hook can take a node out of the
     IN_PLACE tree (remove(), removeChild(), replaceChild() with a safe
     stand-in) leaves no handler anywhere in the deep detached subtree, while
     allow-listed attributes on it are kept and the kept part of the tree is
     still sanitized. */
  var hasEventHandler = function (element) {
    for (var i = 0; i < element.attributes.length; i++) {
      if (/^on/i.test(element.attributes[i].name)) {
        return true;
      }
    }

    return false;
  };
  [
    ['remove()', detachNode],
    [
      'removeChild()',
      function (node) {
        node.parentNode.removeChild(node);
      },
    ],
    [
      'replaceChild()',
      function (node) {
        node.parentNode.replaceChild(
          node.ownerDocument.createElement('span'),
          node
        );
      },
    ],
  ].forEach(function (detachCase) {
    ['beforeSanitizeElements', 'uponSanitizeElement'].forEach(function (hook) {
      QUnit.test(
        'IN_PLACE: ' +
          hook +
          ' detaching via ' +
          detachCase[0] +
          ' neutralizes every descendant of the detached subtree',
        function (assert) {
          withFreshPurify(function (purify) {
            var root = document.createElement('div');
            root.innerHTML =
              '<article onmouseover="alert(1)"><div title="keep">' +
              '<img id="deep" onerror="alert(2)" onload="alert(3)">' +
              '<svg><g onclick="alert(4)"></g></svg>' +
              '<video><source onerror="alert(5)"></video>' +
              '<p><b><i><img onerror="alert(6)"></i></b></p>' +
              '</div></article>' +
              '<p onclick="alert(7)">kept</p>';
            var detached = root.querySelector('article');
            var keepTitle = root.querySelector('[title]');
            var kept = root.querySelector('p[onclick]');

            purify.addHook(hook, function (node) {
              if (node.nodeName === 'ARTICLE') {
                detachCase[1](node);
              }
            });

            var ret = purify.sanitize(root, { IN_PLACE: true });

            assert.strictEqual(ret, root, 'returns the same in-place node');
            assert.notOk(
              ret.querySelector('article'),
              'detached subtree is absent from the returned tree'
            );

            var offenders = [];
            var elements = [detached].concat(
              Array.prototype.slice.call(detached.querySelectorAll('*'))
            );
            for (var i = 0; i < elements.length; i++) {
              if (hasEventHandler(elements[i])) {
                offenders.push(elements[i].nodeName);
              }
            }

            assert.equal(
              offenders.join(','),
              '',
              'no on* handler survives in the hook-detached subtree'
            );
            assert.equal(
              keepTitle.getAttribute('title'),
              'keep',
              'allow-listed attributes on the detached subtree are kept'
            );
            assert.strictEqual(
              kept.getAttribute('onclick'),
              null,
              'the kept part of the tree is still sanitized'
            );
            assert.notOk(
              /\son\w+=/i.test(ret.outerHTML + detached.outerHTML),
              'no handler survives serialization: ' +
                ret.outerHTML +
                detached.outerHTML
            );
          });
        }
      );
    });
  });

  QUnit.test(
    'IN_PLACE: a parent-less root is still sanitized while hooks are registered',
    function (assert) {
      withFreshPurify(function (purify) {
        // The walk root is exempt from the hook-detach early return: a
        // detached IN_PLACE root is legitimate input and must be sanitized.
        var root = document.createElement('div');
        root.setAttribute('onmouseover', 'alert(1)');
        root.innerHTML =
          '<section><img onerror="alert(2)"></section>' +
          '<img id="kept" onerror="alert(3)">';
        var seen = [];
        purify.addHook('beforeSanitizeElements', function (node) {
          seen.push(node.nodeName);
        });
        purify.addHook('uponSanitizeElement', function (node) {
          if (node.nodeName === 'SECTION') {
            detachNode(node);
          }
        });

        var ret = purify.sanitize(root, { IN_PLACE: true });

        assert.strictEqual(ret, root, 'returns the same in-place node');
        assert.strictEqual(
          root.getAttribute('onmouseover'),
          null,
          'on* handler stripped from the parent-less root'
        );
        assert.strictEqual(
          root.querySelector('#kept').getAttribute('onerror'),
          null,
          'on* handler stripped from the kept sibling'
        );
        assert.equal(seen[0], 'DIV', 'the root itself was walked');
      });
    }
  );

  QUnit.test(
    'Hook-detached nodes do not change string and DOM sanitization output',
    function (assert) {
      withFreshPurify(function (purify) {
        purify.addHook('uponSanitizeElement', function (node) {
          if (node.nodeName === 'SECTION') {
            detachNode(node);
          }
        });

        assert.equal(
          purify.sanitize(
            '<section><img src=x onerror=alert(1)></section><p>ok</p>'
          ),
          '<p>ok</p>',
          'string path drops the hook-detached subtree'
        );

        var node = document.createElement('div');
        node.innerHTML = '<section><img onerror=alert(1)></section><p>ok</p>';
        assert.equal(
          purify.sanitize(node, { RETURN_DOM: true }).innerHTML,
          '<div><p>ok</p></div>',
          'DOM path drops the hook-detached subtree'
        );
      });
    }
  );

  QUnit.test(
    'Test protection from prototype pollution of documentMode',
    function (assert) {
      Object.prototype.documentMode = 9;
      try {
        var purify = DOMPurify(window);
        assert.strictEqual(purify.isSupported, true);
        assert.equal(
          purify.sanitize('<img src=x onerror=alert(1)>'),
          '<img src="x">'
        );
      } finally {
        delete Object.prototype.documentMode;
      }
    }
  );
  QUnit.test(
    'Test protection from prototype pollution attacks 1/2',
    function (assert) {
      const obj = JSON.parse(
        '{"ALLOWED_ATTR":["onerror","src"], "documentMode":9}'
      );
      try {
        for (let [k, v] of Object.entries(obj)) {
          Object.prototype[k] = v;
        }
      } catch (e) {}
      var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
      assert.equal(clean, '<img src="x">');
    }
  );
  QUnit.test(
    'Test protection from prototype pollution attacks 2/2',
    function (assert) {
      var obj = {};
      /* Ignore IE10 issue */
      if(obj.__proto__ === undefined) {
        assert.equal(1, 1);
        return true;
      }
      obj.__proto__.hasOwnProperty = Object;
      obj.constructor.prototype.ALLOWED_ATTR = ["src", "onerror"];
      var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
      assert.equal(clean, '<img src="x">');
    }
  );
};
