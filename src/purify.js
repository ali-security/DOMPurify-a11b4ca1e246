import * as TAGS from './tags';
import * as ATTRS from './attrs';
import * as EXPRESSIONS from './regexp';
import {
  addToSet,
  clone,
  create,
  freeze,
  objectKeys,
  arrayForEach,
  arrayIndexOf,
  arrayJoin,
  arrayPop,
  arrayPush,
  arraySlice,
  stringMatch,
  stringReplace,
  stringToLowerCase,
  stringIndexOf,
  stringTrim,
  numberIsNaN,
  regExpTest,
  regExpCreate,
  setAdd,
  setCreate,
  setHas,
  typeErrorCreate,
  lookupGetter,
} from './utils';

const getGlobal = () => (typeof window === 'undefined' ? null : window);

/* Known hook entry points. The `hooks` object is populated on demand, so a
 * plain own-property check against it would reject every legitimate
 * first-time `addHook()` call. The entry point is therefore validated
 * against this fixed set of names instead, which also keeps a non-hook key
 * (e.g. `__proto__`) from resolving off the prototype chain and letting
 * `arrayPush` write to `Object.prototype`. The set is created with a null
 * prototype by `clone`, so the lookup itself is prototype-safe (`addToSet`
 * is not used as it lowercases its entries and hook names are camelCase). */
const HOOK_ENTRY_POINTS = freeze(
  clone({
    beforeSanitizeElements: true,
    uponSanitizeElement: true,
    afterSanitizeElements: true,
    beforeSanitizeAttributes: true,
    uponSanitizeAttribute: true,
    afterSanitizeAttributes: true,
    beforeSanitizeShadowDOM: true,
    uponSanitizeShadowNode: true,
    afterSanitizeShadowDOM: true,
  })
);

/**
 * _isValidHookEntryPoint
 * Checks that a caller-supplied hook entry point is one of the known hooks.
 *
 * @param  {String} entryPoint entry point to validate
 * @return {Boolean} true if the entry point is a known hook
 */
const _isValidHookEntryPoint = function (entryPoint) {
  return HOOK_ENTRY_POINTS[entryPoint] === true;
};

/**
 * Creates a no-op policy for internal use only.
 * Don't export this function outside this module!
 * @param {?TrustedTypePolicyFactory} trustedTypes The policy factory.
 * @param {Document} document The document object (to determine policy name suffix)
 * @return {?TrustedTypePolicy} The policy created (or null, if Trusted Types
 * are not supported).
 */
const _createTrustedTypesPolicy = function (trustedTypes, document) {
  if (
    typeof trustedTypes !== 'object' ||
    typeof trustedTypes.createPolicy !== 'function'
  ) {
    return null;
  }

  // Allow the callers to control the unique policy name
  // by adding a data-tt-policy-suffix to the script element with the DOMPurify.
  // Policy creation with duplicate names throws in Trusted Types.
  let suffix = null;
  const ATTR_NAME = 'data-tt-policy-suffix';
  if (
    document.currentScript &&
    document.currentScript.hasAttribute(ATTR_NAME)
  ) {
    suffix = document.currentScript.getAttribute(ATTR_NAME);
  }

  const policyName = 'dompurify' + (suffix ? '#' + suffix : '');

  try {
    return trustedTypes.createPolicy(policyName, {
      createHTML(html) {
        return html;
      },
    });
  } catch (_) {
    // Policy creation failed (most likely another DOMPurify script has
    // already run). Skip creating the policy, as this will only cause errors
    // if TT are enforced.
    console.warn(
      'TrustedTypes policy ' + policyName + ' could not be created.'
    );
    return null;
  }
};

function createDOMPurify(window = getGlobal()) {
  const DOMPurify = (root) => createDOMPurify(root);

  /**
   * Version label, exposed for easier checks
   * if DOMPurify is up to date or not
   */
  DOMPurify.version = VERSION;

  /**
   * Array of elements that DOMPurify removed during sanitation.
   * Empty if nothing was removed.
   */
  DOMPurify.removed = [];

  if (!window || !window.document || window.document.nodeType !== 9) {
    // Not running in a browser, provide a factory function
    // so that you can pass your own Window
    DOMPurify.isSupported = false;

    return DOMPurify;
  }

  const originalDocument = window.document;
  let removeTitle = false;

  let { document } = window;
  const {
    HTMLTemplateElement,
    Node,
    NodeFilter,
    Element,
    DOMParser,
    trustedTypes,
  } = window;

  const ElementPrototype = Element.prototype;
  const getParentNode = lookupGetter(ElementPrototype, 'parentNode');
  const getChildNodes = lookupGetter(ElementPrototype, 'childNodes');
  const getAttributes = lookupGetter(ElementPrototype, 'attributes');
  const getNodeType =
    Node && Node.prototype ? lookupGetter(Node.prototype, 'nodeType') : null;
  const getNodeName =
    Node && Node.prototype ? lookupGetter(Node.prototype, 'nodeName') : null;
  /* Only cache the shadowRoot getter where the engine implements Shadow DOM,
     lookupGetter's fallback would otherwise warn for every element */
  const getShadowRoot =
    'shadowRoot' in ElementPrototype
      ? lookupGetter(ElementPrototype, 'shadowRoot')
      : null;
  const removeAttribute = lookupGetter(ElementPrototype, 'removeAttribute');

  // As per issue #47, the web-components registry is inherited by a
  // new document created via createHTMLDocument. As per the spec
  // (http://w3c.github.io/webcomponents/spec/custom/#creating-and-passing-registries)
  // a new empty registry is used when creating a template contents owner
  // document, so we use that as our parent document to ensure nothing
  // is inherited.
  if (typeof HTMLTemplateElement === 'function') {
    const template = document.createElement('template');
    if (template.content && template.content.ownerDocument) {
      document = template.content.ownerDocument;
    }
  }

  const trustedTypesPolicy = _createTrustedTypesPolicy(
    trustedTypes,
    originalDocument
  );
  const emptyHTML =
    trustedTypesPolicy && RETURN_TRUSTED_TYPE
      ? trustedTypesPolicy.createHTML('')
      : '';

  const {
    implementation,
    createNodeIterator,
    getElementsByTagName,
    createDocumentFragment,
  } = document;
  const { importNode } = originalDocument;

  /* Only trust an own documentMode, shield it from prototype pollution */
  let documentMode = {};
  try {
    documentMode = clone(document).documentMode ? document.documentMode : {};
  } catch (_) {}

  let hooks = {};

  /**
   * Expose whether this browser supports running the full DOMPurify.
   */
  DOMPurify.isSupported =
    implementation &&
    typeof implementation.createHTMLDocument !== 'undefined' &&
    documentMode !== 9;

  const {
    MUSTACHE_EXPR,
    ERB_EXPR,
    DATA_ATTR,
    ARIA_ATTR,
    IS_SCRIPT_OR_DATA,
    ATTR_WHITESPACE,
  } = EXPRESSIONS;

  let { IS_ALLOWED_URI } = EXPRESSIONS;

  /**
   * We consider the elements and attributes below to be safe. Ideally
   * don't add any new ones but feel free to remove unwanted ones.
   */

  /* allowed element names */
  let ALLOWED_TAGS = null;
  const DEFAULT_ALLOWED_TAGS = addToSet({}, [
    ...TAGS.html,
    ...TAGS.svg,
    ...TAGS.svgFilters,
    ...TAGS.mathMl,
    ...TAGS.text,
  ]);

  /* Allowed attribute names */
  let ALLOWED_ATTR = null;
  const DEFAULT_ALLOWED_ATTR = addToSet({}, [
    ...ATTRS.html,
    ...ATTRS.svg,
    ...ATTRS.mathMl,
    ...ATTRS.xml,
  ]);

  /* Explicitly forbidden tags (overrides ALLOWED_TAGS/ADD_TAGS) */
  let FORBID_TAGS = null;

  /* Explicitly forbidden attributes (overrides ALLOWED_ATTR/ADD_ATTR) */
  let FORBID_ATTR = null;

  /* Decide if ARIA attributes are okay */
  let ALLOW_ARIA_ATTR = true;

  /* Decide if custom data attributes are okay */
  let ALLOW_DATA_ATTR = true;

  /* Decide if unknown protocols are okay */
  let ALLOW_UNKNOWN_PROTOCOLS = false;

  /* Output should be safe for jQuery's $() factory? */
  let SAFE_FOR_JQUERY = false;

  /* Output should be safe for common template engines.
   * This means, DOMPurify removes data attributes, mustaches and ERB
   */
  let SAFE_FOR_TEMPLATES = false;

  /* Output should be safe even for XML used within HTML and alike.
   * This means, DOMPurify removes attributes, comments and raw text
   * elements containing risky content, such as comment closers or end tags
   * of raw text elements (e.g. </xmp>, </noscript>).
   */
  let SAFE_FOR_XML = true;

  /* Decide if document with <html>... should be returned */
  let WHOLE_DOCUMENT = false;

  /* Track whether config is already set on this instance of DOMPurify. */
  let SET_CONFIG = false;

  /* Pristine allowlist bindings captured whenever the configuration is
   * parsed (and therefore also at setConfig() time). Where sanitize() skips
   * re-deriving the sets - the persistent setConfig() path, or a repeated
   * call with the very same config object - they are restored from these
   * before the per-walk hook clone-guard, so a hook's in-call widening
   * cannot carry across calls. Null until the config is parsed; reset by
   * clearConfig(). */
  let PRISTINE_ALLOWED_TAGS = null;
  let PRISTINE_ALLOWED_ATTR = null;

  /* Decide if all elements (e.g. style, script) must be children of
   * document.body. By default, browsers might move them to document.head */
  let FORCE_BODY = false;

  /* Decide if a DOM `HTMLBodyElement` should be returned, instead of a html
   * string (or a TrustedHTML object if Trusted Types are supported).
   * If `WHOLE_DOCUMENT` is enabled a `HTMLHtmlElement` will be returned instead
   */
  let RETURN_DOM = false;

  /* Decide if a DOM `DocumentFragment` should be returned, instead of a html
   * string  (or a TrustedHTML object if Trusted Types are supported) */
  let RETURN_DOM_FRAGMENT = false;

  /* If `RETURN_DOM` or `RETURN_DOM_FRAGMENT` is enabled, decide if the returned DOM
   * `Node` is imported into the current `Document`. If this flag is not enabled the
   * `Node` will belong (its ownerDocument) to a fresh `HTMLDocument`, created by
   * DOMPurify. */
  let RETURN_DOM_IMPORT = false;

  /* Try to return a Trusted Type object instead of a string, retrun a string in
   * case Trusted Types are not supported  */
  let RETURN_TRUSTED_TYPE = false;

  /* Output should be free from DOM clobbering attacks? */
  let SANITIZE_DOM = true;

  /* Keep element content when removing element? */
  let KEEP_CONTENT = true;

  /* If a `Node` is passed to sanitize(), then performs sanitization in-place instead
   * of importing it into a new Document and returning a sanitized copy */
  let IN_PLACE = false;

  /* Allow usage of profiles like html, svg and mathMl */
  let USE_PROFILES = {};

  /* Tags to ignore content of when KEEP_CONTENT is true */
  const FORBID_CONTENTS = addToSet({}, [
    'annotation-xml',
    'audio',
    'colgroup',
    'desc',
    'foreignobject',
    'head',
    'iframe',
    'math',
    'mi',
    'mn',
    'mo',
    'ms',
    'mtext',
    'noembed',
    'noframes',
    'plaintext',
    'script',
    'style',
    'svg',
    'template',
    'thead',
    'title',
    'video',
    'xmp',
  ]);

  /* Tags that are safe for data: URIs */
  let DATA_URI_TAGS = null;
  const DEFAULT_DATA_URI_TAGS = addToSet({}, [
    'audio',
    'video',
    'img',
    'source',
    'image',
    'track',
  ]);

  /* Attributes safe for values like "javascript:" */
  let URI_SAFE_ATTRIBUTES = null;
  const DEFAULT_URI_SAFE_ATTRIBUTES = addToSet({}, [
    'alt',
    'class',
    'for',
    'id',
    'label',
    'name',
    'pattern',
    'placeholder',
    'summary',
    'title',
    'value',
    'style',
    'xmlns',
  ]);

  /* Specify the maximum element nesting depth to prevent mXSS */
  const MAX_NESTING_DEPTH = 255;

  /* Keep a reference to config to pass to hooks */
  let CONFIG = null;

  /* Ideally, do not touch anything below this line */
  /* ______________________________________________ */

  const formElement = document.createElement('form');

  /**
   * _parseConfig
   *
   * @param  {Object} cfg optional config literal
   */
  // eslint-disable-next-line complexity
  const _parseConfig = function (cfg) {
    if (CONFIG && CONFIG === cfg) {
      /* The sets are not re-derived on this path. CONFIG is handed to the
       * hooks as their third argument, so a caller can pass it straight back
       * in - restore the sets from the pristine bindings captured when this
       * config was parsed, otherwise a previous call's hook clone (widened by
       * a hook) would carry over. */
      ALLOWED_TAGS = PRISTINE_ALLOWED_TAGS;
      ALLOWED_ATTR = PRISTINE_ALLOWED_ATTR;
      return;
    }

    /* Shield configuration object from tampering */
    if (!cfg || typeof cfg !== 'object') {
      cfg = {};
    }

    /* Shield configuration object from prototype pollution */
    cfg = clone(cfg);

    /* Set configuration parameters */
    ALLOWED_TAGS =
      'ALLOWED_TAGS' in cfg
        ? addToSet({}, cfg.ALLOWED_TAGS)
        : DEFAULT_ALLOWED_TAGS;
    ALLOWED_ATTR =
      'ALLOWED_ATTR' in cfg
        ? addToSet({}, cfg.ALLOWED_ATTR)
        : DEFAULT_ALLOWED_ATTR;
    URI_SAFE_ATTRIBUTES =
      'ADD_URI_SAFE_ATTR' in cfg
        ? addToSet(clone(DEFAULT_URI_SAFE_ATTRIBUTES), cfg.ADD_URI_SAFE_ATTR)
        : DEFAULT_URI_SAFE_ATTRIBUTES;
    DATA_URI_TAGS =
      'ADD_DATA_URI_TAGS' in cfg
        ? addToSet(clone(DEFAULT_DATA_URI_TAGS), cfg.ADD_DATA_URI_TAGS)
        : DEFAULT_DATA_URI_TAGS;
    FORBID_TAGS = 'FORBID_TAGS' in cfg ? addToSet({}, cfg.FORBID_TAGS) : {};
    FORBID_ATTR = 'FORBID_ATTR' in cfg ? addToSet({}, cfg.FORBID_ATTR) : {};
    USE_PROFILES = 'USE_PROFILES' in cfg ? cfg.USE_PROFILES : false;
    ALLOW_ARIA_ATTR = cfg.ALLOW_ARIA_ATTR !== false; // Default true
    ALLOW_DATA_ATTR = cfg.ALLOW_DATA_ATTR !== false; // Default true
    ALLOW_UNKNOWN_PROTOCOLS = cfg.ALLOW_UNKNOWN_PROTOCOLS || false; // Default false
    SAFE_FOR_JQUERY = cfg.SAFE_FOR_JQUERY || false; // Default false
    SAFE_FOR_TEMPLATES = cfg.SAFE_FOR_TEMPLATES || false; // Default false
    SAFE_FOR_XML = cfg.SAFE_FOR_XML !== false; // Default true
    WHOLE_DOCUMENT = cfg.WHOLE_DOCUMENT || false; // Default false
    RETURN_DOM = cfg.RETURN_DOM || false; // Default false
    RETURN_DOM_FRAGMENT = cfg.RETURN_DOM_FRAGMENT || false; // Default false
    RETURN_DOM_IMPORT = cfg.RETURN_DOM_IMPORT || false; // Default false
    RETURN_TRUSTED_TYPE = cfg.RETURN_TRUSTED_TYPE || false; // Default false
    FORCE_BODY = cfg.FORCE_BODY || false; // Default false
    SANITIZE_DOM = cfg.SANITIZE_DOM !== false; // Default true
    KEEP_CONTENT = cfg.KEEP_CONTENT !== false; // Default true
    IN_PLACE = cfg.IN_PLACE || false; // Default false
    IS_ALLOWED_URI = cfg.ALLOWED_URI_REGEXP || IS_ALLOWED_URI;
    if (SAFE_FOR_TEMPLATES) {
      ALLOW_DATA_ATTR = false;
    }

    if (RETURN_DOM_FRAGMENT) {
      RETURN_DOM = true;
    }

    /* Parse profile info */
    if (USE_PROFILES) {
      ALLOWED_TAGS = addToSet({}, [...TAGS.text]);
      ALLOWED_ATTR = create(null);
      if (USE_PROFILES.html === true) {
        addToSet(ALLOWED_TAGS, TAGS.html);
        addToSet(ALLOWED_ATTR, ATTRS.html);
      }

      if (USE_PROFILES.svg === true) {
        addToSet(ALLOWED_TAGS, TAGS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }

      if (USE_PROFILES.svgFilters === true) {
        addToSet(ALLOWED_TAGS, TAGS.svgFilters);
        addToSet(ALLOWED_ATTR, ATTRS.svg);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }

      if (USE_PROFILES.mathMl === true) {
        addToSet(ALLOWED_TAGS, TAGS.mathMl);
        addToSet(ALLOWED_ATTR, ATTRS.mathMl);
        addToSet(ALLOWED_ATTR, ATTRS.xml);
      }
    }

    /* Merge configuration parameters */
    if (cfg.ADD_TAGS) {
      if (ALLOWED_TAGS === DEFAULT_ALLOWED_TAGS) {
        ALLOWED_TAGS = clone(ALLOWED_TAGS);
      }

      addToSet(ALLOWED_TAGS, cfg.ADD_TAGS);
    }

    if (cfg.ADD_ATTR) {
      if (ALLOWED_ATTR === DEFAULT_ALLOWED_ATTR) {
        ALLOWED_ATTR = clone(ALLOWED_ATTR);
      }

      addToSet(ALLOWED_ATTR, cfg.ADD_ATTR);
    }

    if (cfg.ADD_URI_SAFE_ATTR) {
      addToSet(URI_SAFE_ATTRIBUTES, cfg.ADD_URI_SAFE_ATTR);
    }

    /* Add #text in case KEEP_CONTENT is set to true */
    if (KEEP_CONTENT) {
      ALLOWED_TAGS['#text'] = true;
    }

    /* Add html, head and body to ALLOWED_TAGS in case WHOLE_DOCUMENT is true */
    if (WHOLE_DOCUMENT) {
      addToSet(ALLOWED_TAGS, ['html', 'head', 'body']);
    }

    /* Add tbody to ALLOWED_TAGS in case tables are permitted, see #286, #365 */
    if (ALLOWED_TAGS.table) {
      addToSet(ALLOWED_TAGS, ['tbody']);
      delete FORBID_TAGS.tbody;
    }

    // Prevent further manipulation of configuration.
    // Not available in IE8, Safari 5, etc.
    if (freeze) {
      freeze(cfg);
    }

    CONFIG = cfg;

    /* Capture the freshly derived allowlists. sanitize() restores the sets
     * from these whenever it skips re-deriving them, keeping a hook's
     * in-call widening scoped to the call it happened in. */
    PRISTINE_ALLOWED_TAGS = ALLOWED_TAGS;
    PRISTINE_ALLOWED_ATTR = ALLOWED_ATTR;
  };

  /**
   * _forceRemove
   *
   * @param  {Node} node a DOM node
   */
  const _forceRemove = function (node) {
    arrayPush(DOMPurify.removed, { element: node });
    try {
      // eslint-disable-next-line unicorn/prefer-node-remove
      node.parentNode.removeChild(node);
    } catch (_) {
      node.outerHTML = emptyHTML;
    }
  };

  /**
   * _removeAttribute
   *
   * @param  {String} name an Attribute name
   * @param  {Node} node a DOM node
   */
  const _removeAttribute = function (name, node) {
    try {
      arrayPush(DOMPurify.removed, {
        attribute: node.getAttributeNode(name),
        from: node,
      });
    } catch (_) {
      arrayPush(DOMPurify.removed, {
        attribute: null,
        from: node,
      });
    }

    node.removeAttribute(name);
  };

  /**
   * _initDocument
   *
   * @param  {String} dirty a string of dirty markup
   * @return {Document} a DOM, filled with the dirty markup
   */
  const _initDocument = function (dirty) {
    /* Create a HTML document */
    let doc;
    let leadingWhitespace;

    if (FORCE_BODY) {
      dirty = '<remove></remove>' + dirty;
    } else {
      /* If FORCE_BODY isn't used, leading whitespace needs to be preserved manually */
      const matches = stringMatch(dirty, /^[\r\n\t ]+/);
      leadingWhitespace = matches && matches[0];
    }

    const dirtyPayload = trustedTypesPolicy
      ? trustedTypesPolicy.createHTML(dirty)
      : dirty;
    /* Use the DOMParser API by default, fallback later if needs be */
    try {
      doc = new DOMParser().parseFromString(dirtyPayload, 'text/html');
    } catch (_) {}

    /* Remove title to fix a mXSS bug in older MS Edge */
    if (removeTitle) {
      addToSet(FORBID_TAGS, ['title']);
    }

    /* Use createHTMLDocument in case DOMParser is not available */
    if (!doc || !doc.documentElement) {
      doc = implementation.createHTMLDocument('');
      const { body } = doc;
      body.parentNode.removeChild(body.parentNode.firstElementChild);
      body.outerHTML = dirtyPayload;
    }

    if (dirty && leadingWhitespace) {
      doc.body.insertBefore(
        document.createTextNode(leadingWhitespace),
        doc.body.childNodes[0] || null
      );
    }

    /* Work on whole document or just its body */
    return getElementsByTagName.call(doc, WHOLE_DOCUMENT ? 'html' : 'body')[0];
  };

  /* Here we test for a broken feature in Edge that might cause mXSS */
  if (DOMPurify.isSupported) {
    (function () {
      try {
        const doc = _initDocument('<x/><title>&lt;/title&gt;&lt;img&gt;');
        if (regExpTest(/<\/title/, doc.querySelector('title').innerHTML)) {
          removeTitle = true;
        }
      } catch (_) {}
    })();
  }

  /**
   * _createIterator
   *
   * @param  {Document} root document/fragment to create iterator for
   * @return {Iterator} iterator instance
   */
  const _createIterator = function (root) {
    return createNodeIterator.call(
      root.ownerDocument || root,
      root,
      NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_COMMENT | NodeFilter.SHOW_TEXT,
      () => {
        return NodeFilter.FILTER_ACCEPT;
      },
      false
    );
  };

  /**
   * _getNodeType
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): read nodeType through the cached
   * Node.prototype getter instead of relying on `instanceof` checks against
   * this window's constructors. A node minted in another realm (e.g. a
   * same-origin iframe document) is an instance of the foreign realm's
   * constructors, so `instanceof` short-circuits to false for it, while the
   * getter reads the node's internal slot and works for nodes of any realm.
   * It also can not be shadowed by a clobbering form descendant.
   *
   * @param  {Node} value object to read the node type of
   * @return {Number|null} the node type, or null if value is not a DOM node
   */
  const _getNodeType = function (value) {
    if (!getNodeType || typeof value !== 'object' || value === null) {
      return null;
    }

    try {
      return getNodeType(value);
    } catch (_) {
      return null;
    }
  };

  /**
   * _getNodeName
   *
   * GHSA-x4vx-rjvf-j5p4: read nodeName through the cached Node.prototype
   * getter instead of trusting the instance-visible property. A live node
   * handed in with IN_PLACE can carry an own `nodeName` (e.g. a <script>
   * defining nodeName as "DIV"), which a direct read returns while the
   * getter reads the node's internal slot. The getter works for nodes of
   * any realm. Falls back to the direct read only where the getter is not
   * available.
   *
   * @param  {Node} node node to read the name of
   * @return {String} the node name
   */
  const _getNodeName = function (node) {
    if (getNodeName) {
      try {
        const nodeName = getNodeName(node);
        if (typeof nodeName === 'string') {
          return nodeName;
        }
      } catch (_) {}
    }

    return node.nodeName;
  };

  /**
   * _isDocumentFragment
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): `value instanceof DocumentFragment`
   * is realm-bound, a fragment from a foreign realm (e.g. the content of a
   * <template> created in an iframe document) failed the check and its
   * contents were never walked. Compare the realm-independent nodeType
   * against DOCUMENT_FRAGMENT_NODE (11) instead.
   *
   * @param  {*} value object to check
   * @return {Boolean} true if value is a DocumentFragment from any realm
   */
  const _isDocumentFragment = function (value) {
    return _getNodeType(value) === 11;
  };

  /**
   * _isClobbered
   *
   * Realm safety (GHSA-hpcv-96wg-7vj8): every check in here has to work for
   * nodes of a foreign realm too. Text and comment nodes are recognized by
   * their realm-independent nodeType, and the NamedNodeMap check compares the
   * direct .attributes read against the cached Element.prototype getter
   * instead of using `instanceof NamedNodeMap`. A clobbering child (e.g.
   * <input name="attributes">) makes the two reads diverge, while a clean
   * element of any realm returns its canonical NamedNodeMap for both.
   *
   * @param  {Node} elm element to check for clobbering attacks
   * @return {Boolean} true if clobbered, false if safe
   */
  // eslint-disable-next-line complexity
  const _isClobbered = function (elm) {
    const nodeType = _getNodeType(elm);
    if (nodeType === 3 || nodeType === 4 || nodeType === 8) {
      return false;
    }

    if (
      (typeof elm.__depth !== 'undefined' && typeof elm.__depth !== 'number') ||
      (typeof elm.__removalCount !== 'undefined' &&
        typeof elm.__removalCount !== 'number') ||
      typeof elm.nodeName !== 'string' ||
      /* NodeName spoofing probe (GHSA-x4vx-rjvf-j5p4). A live node can
         define an own nodeName (e.g. a <script> claiming to be a "DIV"),
         which diverges from the cached Node.prototype getter. Such a node
         is hostile, treat it like any other clobbered node. */
      elm.nodeName !== _getNodeName(elm) ||
      typeof elm.textContent !== 'string' ||
      typeof elm.removeChild !== 'function' ||
      elm.attributes !== getAttributes(elm) ||
      typeof elm.removeAttribute !== 'function' ||
      typeof elm.setAttribute !== 'function' ||
      typeof elm.namespaceURI !== 'string' ||
      typeof elm.insertBefore !== 'function' ||
      typeof elm.hasChildNodes !== 'function' ||
      /* NodeType clobbering probe. The cached Node.prototype.nodeType getter
         returns the integer 1 for any element regardless of realm, while a
         direct read on a clobbered form (e.g. <input name="nodeType">)
         returns the named child element. This removes a residual clobbering
         surface, the nesting depth bookkeeping and several branches compare
         currentNode.nodeType directly. Skipped when the getter is not
         available, so a missing getter can not flag every element. */
      (nodeType !== null && elm.nodeType !== nodeType) ||
      /* HTMLFormElement has [LegacyOverrideBuiltIns]: a descendant named
         "childNodes" shadows the prototype getter. Compare the direct read
         to the cached Node.prototype getter, the two values differ when the
         form's named-property getter intercepts the read. This catches every
         clobbering child type (input, select, etc.) */
      elm.childNodes !== getChildNodes(elm)
    ) {
      return true;
    }

    return false;
  };

  /**
   * _isDepthTampered
   *
   * @param  {Node} elm element to check the nesting depth bookkeeping of
   * @return {Boolean} true if __depth or __removalCount are not sane numbers,
   * e.g. because they were clobbered or polluted through Object.prototype
   */
  const _isDepthTampered = function (elm) {
    const removalCount = elm.__removalCount || 0;

    return (
      typeof elm.__depth !== 'number' ||
      elm.__depth < 1 ||
      typeof removalCount !== 'number' ||
      removalCount < 0
    );
  };

  /**
   * _isNode
   *
   * @param  {Node} obj object to check whether it's a DOM node
   * @return {Boolean} true is object is a DOM node
   */
  const _isNode = function (object) {
    /* Trust the prototype chain first. A form can clobber nodeType and
       nodeName through named descendants, which fails the duck-typing below
       and would stringify an IN_PLACE root instead of sanitizing the node,
       leaving it untouched. GHSA-r47g-fvhr-h676. */
    if (typeof Node === 'function' && object instanceof Node) {
      return true;
    }

    /* The prototype chain check is realm-bound, a node of a foreign realm
       (e.g. a same-origin iframe document) fails it. Read nodeType through
       the cached Node.prototype getter, which works across realms and can
       not be clobbered by a form's named descendants. GHSA-hpcv-96wg-7vj8. */
    if (typeof _getNodeType(object) === 'number') {
      return true;
    }

    return typeof Node === 'object'
      ? object instanceof Node
      : object &&
          typeof object === 'object' &&
          typeof object.nodeType === 'number' &&
          typeof object.nodeName === 'string';
  };

  /**
   * _hasHooks
   * Check whether at least one hook is registered for an entry point.
   * The `hooks` object is populated on demand, so the array may be absent.
   *
   * @param  {String} entryPoint  Name of the hook's entry point
   * @return {Boolean} true if a hook is registered for the entry point
   */
  const _hasHooks = function (entryPoint) {
    return Boolean(hooks[entryPoint] && hooks[entryPoint].length > 0);
  };

  /**
   * _executeHook
   * Execute user configurable hooks
   *
   * @param  {String} entryPoint  Name of the hook's entry point
   * @param  {Node} currentNode node to work on with the hook
   * @param  {Object} data additional hook parameters
   */
  const _executeHook = function (entryPoint, currentNode, data) {
    if (!hooks[entryPoint]) {
      return;
    }

    arrayForEach(hooks[entryPoint], (hook) => {
      hook.call(DOMPurify, currentNode, data, CONFIG);
    });
  };

  /**
   * _stripDisallowedAttributes
   *
   * Removes every attribute the active configuration does not allow from a
   * single element, using the same allowlist as the main attribute pass (so
   * `on*` handlers go, but no `/^on/` blocklist is introduced). Used only to
   * neutralise nodes that are being discarded from an in-place tree.
   *
   * @param  {Element} element the element to strip
   */
  const _stripDisallowedAttributes = function (element) {
    let attributes = null;
    try {
      attributes = getAttributes(element);
    } catch (_) {}

    if (!attributes) {
      return;
    }

    for (let i = attributes.length - 1; i >= 0; --i) {
      const attribute = attributes[i];
      const name = attribute && attribute.name;
      if (typeof name !== 'string' || ALLOWED_ATTR[stringToLowerCase(name)]) {
        continue;
      }

      try {
        removeAttribute(element, name);
      } catch (_) {
        /* A doomed node with a broken removeAttribute, ignore */
      }
    }
  };

  /**
   * _neutralizeSubtree
   *
   * On the IN_PLACE path the caller built the tree in the live document, so
   * a node detached from it can still carry an already-queued resource event
   * (an `<img onerror>` / `<video>` that began loading), which fires in page
   * scope after sanitize returns even though the node never reached the
   * returned tree. This walks such a discarded subtree and strips every
   * attribute the active configuration does not allow, so `on*` handlers
   * are cancelled through the SAME allowlist that governs kept nodes. It runs
   * synchronously before sanitize returns, i.e. before any queued event can
   * fire. Hook-free by design: these nodes leave the output, so firing
   * attribute hooks for them would be surprising. The walk is iterative and
   * uses the cached getters, so deep or clobbered subtrees are handled.
   *
   * @param  {Node} root the root of a discarded subtree to neutralise
   */
  const _neutralizeSubtree = function (root) {
    const stack = [root];

    while (stack.length > 0) {
      const node = arrayPop(stack);
      const nodeType = getNodeType ? _getNodeType(node) : node.nodeType;

      if (nodeType === 1) {
        _stripDisallowedAttributes(node);
      }

      let childNodes = null;
      try {
        childNodes = getChildNodes(node);
      } catch (_) {}

      if (childNodes) {
        for (let i = childNodes.length - 1; i >= 0; --i) {
          arrayPush(stack, childNodes[i]);
        }
      }
    }
  };

  /**
   * _collectLiveNodes
   *
   * Every node reachable from `root`, in document order: its light-DOM
   * subtree plus the subtrees of open attached shadow roots, recursively
   * (each shadow root is listed right after its host, then its content).
   * <template>.content is not entered - its nodes live in an inert document
   * and neither fetch resources nor run handlers. Closed shadow roots are not
   * reachable from script at all. Iterative and clobber-safe (cached
   * getters), like _neutralizeSubtree, so a deep or clobbering tree can
   * neither overflow the call stack nor hide a subtree.
   *
   * @param  {Node} root the in-place root
   * @return {Array} the nodes, root first
   */
  const _collectLiveNodes = function (root) {
    const nodes = [];
    const stack = [root];

    while (stack.length > 0) {
      const node = arrayPop(stack);
      arrayPush(nodes, node);

      /* Pushed first, so processed after the host's light children. */
      if (getShadowRoot && _getNodeType(node) === 1) {
        let shadowRoot = null;
        try {
          shadowRoot = getShadowRoot(node);
        } catch (_) {}

        if (_isDocumentFragment(shadowRoot)) {
          arrayPush(stack, shadowRoot);
        }
      }

      let childNodes = null;
      try {
        childNodes = getChildNodes(node);
      } catch (_) {}

      if (childNodes) {
        for (let i = childNodes.length - 1; i >= 0; --i) {
          arrayPush(stack, childNodes[i]);
        }
      }
    }

    return nodes;
  };

  /**
   * _neutralizeEscapedElements
   *
   * IN_PLACE completion of the hook-detach neutralization, keyed on the tree
   * rather than on the node a hook was called for: every element that was
   * under the root when sanitize() started, and is no longer under it now,
   * has its non-allow-listed attributes stripped before sanitize() returns
   * or rethrows.
   *
   * The inline neutralize in _sanitizeElements only notices a hook detaching
   * the node it was called for. Anything else that leaves the tree mid-walk -
   * a hook removing the current node's parent/ancestor or a not-yet-visited
   * sibling, a hook moving a subtree out of the root, or a page custom
   * element's attributeChangedCallback reacting to one of our own
   * removeAttribute calls - takes its subtree out of the walker's reach
   * unsanitized, and a handler there (an <img onerror> that started loading
   * when the caller built the live tree) fires in page scope after we
   * return. Comparing a snapshot taken before any hook or reaction could run
   * against what is still reachable covers every such route at once.
   * GHSA-mrv2-3pqr-j5jr.
   *
   * Strips per element rather than per detached subtree: each descendant of
   * an escaped subtree is itself in the snapshot, so this stays linear in
   * tree size. Elements DOMPurify removed itself are stripped as well, which
   * is harmless for nodes that leave the output anyway.
   *
   * @param  {Node} root the in-place root
   * @param  {Array} before the root's nodes, collected before the walk
   */
  const _neutralizeEscapedElements = function (root, before) {
    const reachable = setCreate();
    arrayForEach(_collectLiveNodes(root), (node) => {
      setAdd(reachable, node);
    });
    arrayForEach(before, (node) => {
      const nodeType = getNodeType ? _getNodeType(node) : node.nodeType;
      if (nodeType === 1 && !setHas(reachable, node)) {
        _stripDisallowedAttributes(node);
      }
    });
  };

  /**
   * _sanitizeElements
   *
   * @protect nodeName
   * @protect textContent
   * @protect removeChild
   *
   * @param   {Node} currentNode to check for permission to exist
   * @param   {Node} root the root node of the current walk
   * @return  {Boolean} true if node was killed, false if left alive
   */
  // eslint-disable-next-line complexity
  const _sanitizeElements = function (currentNode, root) {
    let content;

    /* Execute a hook if present */
    _executeHook('beforeSanitizeElements', currentNode, null);

    /* A hook may have detached the node - on the IN_PLACE path treat it as
       removed (see the detached-node comment after the uponSanitizeElement
       hook below), neutralizing the detached subtree first so a queued
       resource handler on it cannot fire in page scope after we return. */
    if (
      IN_PLACE &&
      currentNode !== root &&
      getParentNode(currentNode) === null
    ) {
      _neutralizeSubtree(currentNode);
      return true;
    }

    /* Check if element is clobbered or can clobber */
    if (_isClobbered(currentNode)) {
      _forceRemove(currentNode);
      return true;
    }

    /* Now let's check the element's type and name. The name is read through
       the cached getter, an own nodeName property can not spoof it
       (GHSA-x4vx-rjvf-j5p4) */
    const tagName = stringToLowerCase(_getNodeName(currentNode));

    /* Execute a hook if present */
    _executeHook('uponSanitizeElement', currentNode, {
      tagName,
      allowedTags: ALLOWED_TAGS,
    });

    /* A hook may have detached the node (e.g. via the documented
       node.remove() pattern). That takes the subtree out of the tree before
       the walker reaches its descendants, so they are never visited. Nodes
       detached by hooks stay the hook's responsibility for placement, but on
       the IN_PLACE path a hook-detached subtree can still hold a queued
       resource-event handler - e.g. an <img onerror> that began loading when
       the caller built the live tree - which fires in page scope after
       sanitize returns even though the handler never reached the returned
       tree. So on the IN_PLACE path we neutralize the detached subtree inline
       here, stripping its non-allow-listed attributes, and treat the node as
       removed. The walk root is exempt: a detached IN_PLACE root is
       legitimate input and must still be fully sanitized. This only sees the
       node the hook was called for; a hook that detaches some OTHER node (an
       ancestor, a later sibling) is caught by _neutralizeEscapedElements at
       the end of the call. */
    if (
      IN_PLACE &&
      currentNode !== root &&
      getParentNode(currentNode) === null
    ) {
      _neutralizeSubtree(currentNode);
      return true;
    }

    /* Take care of an mXSS pattern using p, br inside svg, math */
    if (
      (tagName === 'svg' || tagName === 'math') &&
      currentNode.querySelectorAll('p, br, form, table').length !== 0
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove element if anything forbids its presence */
    if (!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]) {
      /* Keep content except for bad-listed elements */
      if (
        KEEP_CONTENT &&
        !FORBID_CONTENTS[tagName] &&
        typeof currentNode.insertAdjacentHTML === 'function'
      ) {
        try {
          const htmlToInsert = currentNode.innerHTML;
          currentNode.insertAdjacentHTML(
            'AfterEnd',
            trustedTypesPolicy
              ? trustedTypesPolicy.createHTML(htmlToInsert)
              : htmlToInsert
          );
          /*
             Count removals for an accurate element nesting depth
             measurement to prevent mXSS attacks
          */
          const newNode = currentNode.nextSibling;
          if (newNode) {
            newNode.__removalCount = (currentNode.__removalCount || 0) + 1;
          }
        } catch (_) {}
      }

      _forceRemove(currentNode);
      return true;
    }

    /* Remove in case a noscript/noembed XSS is suspected */
    if (
      tagName === 'noscript' &&
      regExpTest(/<\/noscript/i, currentNode.innerHTML)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    if (
      tagName === 'noembed' &&
      regExpTest(/<\/noembed/i, currentNode.innerHTML)
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Remove raw text content (e.g. of style) that is serialized verbatim
     * and could close a wrapping raw text element when re-parsed */
    if (
      SAFE_FOR_XML &&
      !currentNode.firstElementChild &&
      (!currentNode.content || !currentNode.content.firstElementChild) &&
      regExpTest(
        /<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,
        currentNode.innerHTML
      ) &&
      regExpTest(
        /<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,
        currentNode.textContent
      )
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Comment data is serialized verbatim as well, remove comments that
     * could close a wrapping raw text element when re-parsed */
    if (
      SAFE_FOR_XML &&
      currentNode.nodeType === 8 &&
      regExpTest(
        /<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,
        currentNode.data
      )
    ) {
      _forceRemove(currentNode);
      return true;
    }

    /* Convert markup to cover jQuery behavior */
    if (
      SAFE_FOR_JQUERY &&
      !currentNode.firstElementChild &&
      (!currentNode.content || !currentNode.content.firstElementChild) &&
      regExpTest(/</g, currentNode.textContent)
    ) {
      arrayPush(DOMPurify.removed, { element: currentNode.cloneNode() });
      if (currentNode.innerHTML) {
        currentNode.innerHTML = stringReplace(
          currentNode.innerHTML,
          /</g,
          '&lt;'
        );
      } else {
        currentNode.innerHTML = stringReplace(
          currentNode.textContent,
          /</g,
          '&lt;'
        );
      }
    }

    /* Sanitize element content to be template-safe */
    if (SAFE_FOR_TEMPLATES && currentNode.nodeType === 3) {
      /* Get the element's text content */
      content = currentNode.textContent;
      content = stringReplace(content, MUSTACHE_EXPR, ' ');
      content = stringReplace(content, ERB_EXPR, ' ');
      if (currentNode.textContent !== content) {
        arrayPush(DOMPurify.removed, { element: currentNode.cloneNode() });
        currentNode.textContent = content;
      }
    }

    /* Execute a hook if present */
    _executeHook('afterSanitizeElements', currentNode, null);

    return false;
  };

  /**
   * _isValidAttribute
   *
   * @param  {string} lcTag Lowercase tag name of containing element.
   * @param  {string} lcName Lowercase attribute name.
   * @param  {string} value Attribute value.
   * @return {Boolean} Returns true if `value` is valid, otherwise false.
   */
  // eslint-disable-next-line complexity
  const _isValidAttribute = function (lcTag, lcName, value) {
    /* FORBID_ATTR must always win, even if ALLOW_DATA_ATTR or
       ALLOW_ARIA_ATTR would allow it */
    if (FORBID_ATTR[lcName]) {
      return false;
    }

    /* Make sure attribute cannot clobber */
    if (
      SANITIZE_DOM &&
      (lcName === 'id' || lcName === 'name') &&
      (value in document || value in formElement)
    ) {
      return false;
    }

    /* Allow valid data-* attributes: At least one character after "-"
        (https://html.spec.whatwg.org/multipage/dom.html#embedding-custom-non-visible-data-with-the-data-*-attributes)
        XML-compatible (https://html.spec.whatwg.org/multipage/infrastructure.html#xml-compatible and http://www.w3.org/TR/xml/#d0e804)
        We don't need to check the value; it's always URI safe. */
    if (ALLOW_DATA_ATTR && regExpTest(DATA_ATTR, lcName)) {
      // This attribute is safe
    } else if (ALLOW_ARIA_ATTR && regExpTest(ARIA_ATTR, lcName)) {
      // This attribute is safe
      /* Otherwise, check the name is permitted */
    } else if (!ALLOWED_ATTR[lcName] || FORBID_ATTR[lcName]) {
      return false;

      /* Check value is safe. First, is attr inert? If so, is safe */
    } else if (URI_SAFE_ATTRIBUTES[lcName]) {
      // This attribute is safe
      /* Check no script, data or unknown possibly unsafe URI
        unless we know URI values are safe for that attribute */
    } else if (
      regExpTest(IS_ALLOWED_URI, stringReplace(value, ATTR_WHITESPACE, ''))
    ) {
      // This attribute is safe
      /* Keep image data URIs alive if src/xlink:href is allowed */
      /* Further prevent gadget XSS for dynamically built script tags */
    } else if (
      (lcName === 'src' || lcName === 'xlink:href' || lcName === 'href') &&
      lcTag !== 'script' &&
      stringIndexOf(value, 'data:') === 0 &&
      DATA_URI_TAGS[lcTag]
    ) {
      // This attribute is safe
      /* Allow unknown protocols: This provides support for links that
        are handled by protocol handlers which may be unknown ahead of
        time, e.g. fb:, spotify: */
    } else if (
      ALLOW_UNKNOWN_PROTOCOLS &&
      !regExpTest(IS_SCRIPT_OR_DATA, stringReplace(value, ATTR_WHITESPACE, ''))
    ) {
      // This attribute is safe
      /* Check for binary attributes */
      // eslint-disable-next-line no-negated-condition
    } else if (!value) {
      // Binary attributes are safe at this point
      /* Anything else, presume unsafe, do not add it back */
    } else {
      return false;
    }

    return true;
  };

  /**
   * _sanitizeAttributes
   *
   * @protect attributes
   * @protect nodeName
   * @protect removeAttribute
   * @protect setAttribute
   *
   * @param  {Node} currentNode to sanitize
   */
  // eslint-disable-next-line complexity
  const _sanitizeAttributes = function (currentNode) {
    let attr;
    let value;
    let lcName;
    let idAttr;
    let l;
    /* Execute a hook if present */
    _executeHook('beforeSanitizeAttributes', currentNode, null);

    let { attributes } = currentNode;

    /* Check if we have attributes; if not we might have a text node */
    if (!attributes) {
      return;
    }

    const hookEvent = {
      attrName: '',
      attrValue: '',
      keepAttr: true,
      allowedAttributes: ALLOWED_ATTR,
    };
    l = attributes.length;

    /* Go backwards over all attributes; safely remove bad ones */
    while (l--) {
      attr = attributes[l];
      const { name, namespaceURI } = attr;
      value = stringTrim(attr.value);
      lcName = stringToLowerCase(name);

      /* Execute a hook if present */
      hookEvent.attrName = lcName;
      hookEvent.attrValue = value;
      hookEvent.keepAttr = true;
      hookEvent.forceKeepAttr = undefined; // Allows developers to see this is a property they can set
      _executeHook('uponSanitizeAttribute', currentNode, hookEvent);
      value = hookEvent.attrValue;
      /* Did the hooks approve of the attribute? */
      if (hookEvent.forceKeepAttr) {
        continue;
      }

      /* Remove attribute */
      // Safari (iOS + Mac), last tested v8.0.5, crashes if you try to
      // remove a "name" attribute from an <img> tag that has an "id"
      // attribute at the time.
      if (
        lcName === 'name' &&
        currentNode.nodeName === 'IMG' &&
        attributes.id
      ) {
        idAttr = attributes.id;
        attributes = arraySlice(attributes, []);
        _removeAttribute('id', currentNode);
        _removeAttribute(name, currentNode);
        if (arrayIndexOf(attributes, idAttr) > l) {
          currentNode.setAttribute('id', idAttr.value);
        }
      } else if (
        // This works around a bug in Safari, where input[type=file]
        // cannot be dynamically set after type has been removed
        currentNode.nodeName === 'INPUT' &&
        lcName === 'type' &&
        value === 'file' &&
        hookEvent.keepAttr &&
        (ALLOWED_ATTR[lcName] || !FORBID_ATTR[lcName])
      ) {
        continue;
      } else {
        // This avoids a crash in Safari v9.0 with double-ids.
        // The trick is to first set the id to be empty and then to
        // remove the attribute
        if (name === 'id') {
          currentNode.setAttribute(name, '');
        }

        _removeAttribute(name, currentNode);
      }

      /* Did the hooks approve of the attribute? */
      if (!hookEvent.keepAttr) {
        continue;
      }

      /* Work around a security issue in jQuery 3.0 */
      if (SAFE_FOR_JQUERY && regExpTest(/\/>/i, value)) {
        _removeAttribute(name, currentNode);
        continue;
      }

      /* Work around a security issue with comments inside attributes */
      if (
        SAFE_FOR_XML &&
        regExpTest(
          /((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,
          value
        )
      ) {
        _removeAttribute(name, currentNode);
        continue;
      }

      /* Take care of an mXSS pattern using namespace switches */
      if (
        regExpTest(/svg|math/i, currentNode.namespaceURI) &&
        regExpTest(
          regExpCreate(
            '</(' + arrayJoin(objectKeys(FORBID_CONTENTS), '|') + ')',
            'i'
          ),
          value
        )
      ) {
        _removeAttribute(name, currentNode);
        continue;
      }

      /* Sanitize attribute content to be template-safe */
      if (SAFE_FOR_TEMPLATES) {
        value = stringReplace(value, MUSTACHE_EXPR, ' ');
        value = stringReplace(value, ERB_EXPR, ' ');
      }

      /* Is `value` valid for this attribute? The tag name is read through
         the cached getter, so a spoofed nodeName (e.g. an <a> claiming to
         be an "IMG") can not unlock data: URIs (GHSA-x4vx-rjvf-j5p4) */
      const lcTag = stringToLowerCase(_getNodeName(currentNode));
      if (!_isValidAttribute(lcTag, lcName, value)) {
        continue;
      }

      /* Handle invalid data-* attribute set by try-catching it */
      try {
        if (namespaceURI) {
          currentNode.setAttributeNS(namespaceURI, name, value);
        } else {
          /* Fallback to setAttribute() for browser-unrecognized namespaces e.g. "x-schema". */
          currentNode.setAttribute(name, value);
        }

        arrayPop(DOMPurify.removed);
      } catch (_) {}
    }

    /* Execute a hook if present */
    _executeHook('afterSanitizeAttributes', currentNode, null);
  };

  /**
   * _sanitizeShadowDOM
   *
   * @param  {DocumentFragment} fragment to iterate over recursively
   */
  const _sanitizeShadowDOM = function (fragment) {
    let shadowNode;
    const shadowIterator = _createIterator(fragment);

    /* Execute a hook if present */
    _executeHook('beforeSanitizeShadowDOM', fragment, null);

    while ((shadowNode = shadowIterator.nextNode())) {
      /* Execute a hook if present */
      _executeHook('uponSanitizeShadowNode', shadowNode, null);

      /* Sanitize tags and elements */
      if (_sanitizeElements(shadowNode, fragment)) {
        continue;
      }

      const parentNode = getParentNode(shadowNode);

      /* Set the nesting depth of an element */
      if (shadowNode.nodeType === 1) {
        if (parentNode && parentNode.__depth) {
          /*
            We want the depth of the node in the original tree, which can
            change when it's removed from its parent.
          */
          shadowNode.__depth =
            (shadowNode.__removalCount || 0) + parentNode.__depth + 1;
        } else {
          shadowNode.__depth = 1;
        }
      }

      /*
       * Remove an element if nested too deeply to avoid mXSS
       * or if the __depth might have been tampered with
       */
      if (
        shadowNode.__depth >= MAX_NESTING_DEPTH ||
        numberIsNaN(shadowNode.__depth) ||
        (shadowNode.nodeType === 1 && _isDepthTampered(shadowNode))
      ) {
        _forceRemove(shadowNode);
      }

      /* Deep shadow DOM detected. Realm-safe check (GHSA-hpcv-96wg-7vj8):
         nodeType-based detection instead of instanceof, so <template>.content
         of a foreign realm is walked too. */
      if (_isDocumentFragment(shadowNode.content)) {
        shadowNode.content.__depth = shadowNode.__depth;
        _sanitizeShadowDOM(shadowNode.content);
      }

      /* An element iterated here may itself host an attached shadow root.
         The NodeIterator does not enter shadow trees, so a shadow root
         nested inside <template>.content was reached by no walk at all (the
         template-content recursion above iterates the content but never
         inspected shadowRoot), and its payload survived. Walk it explicitly.
         The shadowRoot is read through the cached Element.prototype getter,
         and only for element nodes, as the iterator also surfaces text and
         comment nodes. CVE-2026-49978. */
      if (getShadowRoot && _getNodeType(shadowNode) === 1) {
        const innerShadowRoot = getShadowRoot(shadowNode);
        if (_isDocumentFragment(innerShadowRoot)) {
          innerShadowRoot.__depth = shadowNode.__depth;
          _sanitizeShadowDOM(innerShadowRoot);
        }
      }

      /* Check attributes, sanitize if necessary */
      _sanitizeAttributes(shadowNode);
    }

    /* Execute a hook if present */
    _executeHook('afterSanitizeShadowDOM', fragment, null);
  };

  /**
   * Sanitize
   * Public method providing core sanitation functionality
   *
   * @param {String|Node} dirty string or DOM node
   * @param {Object} configuration object
   */
  // eslint-disable-next-line complexity
  DOMPurify.sanitize = function (dirty, cfg) {
    let body;
    let importedNode;
    let currentNode;
    let oldNode;
    let returnNode;
    /* IN_PLACE only: the root's nodes before any hook or custom-element
       reaction can run, for _neutralizeEscapedElements */
    let inPlaceNodes = [];
    /* Make sure we have a string to sanitize.
      DO NOT return early, as this will return the wrong type if
      the user has requested a DOM object rather than a string */
    if (!dirty) {
      dirty = '<!-->';
    }

    /* Stringify, in case dirty is an object */
    if (typeof dirty !== 'string' && !_isNode(dirty)) {
      // eslint-disable-next-line no-negated-condition
      if (typeof dirty.toString !== 'function') {
        throw typeErrorCreate('toString is not a function');
      } else {
        dirty = dirty.toString();
        if (typeof dirty !== 'string') {
          throw typeErrorCreate('dirty is not a string, aborting');
        }
      }
    }

    /* Check we can run. Otherwise fall back or ignore */
    if (!DOMPurify.isSupported) {
      if (
        typeof window.toStaticHTML === 'object' ||
        typeof window.toStaticHTML === 'function'
      ) {
        if (typeof dirty === 'string') {
          return window.toStaticHTML(dirty);
        }

        if (_isNode(dirty)) {
          return window.toStaticHTML(dirty.outerHTML);
        }
      }

      return dirty;
    }

    /* Assign config vars */
    if (SET_CONFIG) {
      /* Persistent setConfig() path: _parseConfig is skipped, so the sets are
       * not re-derived per call. Restore them from the pristine bindings
       * captured at setConfig() time so a previous call's hook clone (mutated
       * below) does not carry over. */
      ALLOWED_TAGS = PRISTINE_ALLOWED_TAGS;
      ALLOWED_ATTR = PRISTINE_ALLOWED_ATTR;
    } else {
      _parseConfig(cfg);
    }

    /* Clone the hook-mutable allowlists before the walk whenever an
     * uponSanitize* hook is registered. The hook event exposes ALLOWED_TAGS
     * and ALLOWED_ATTR by reference (as allowedTags / allowedAttributes), so
     * a hook that widens them would otherwise mutate the shared set
     * permanently: across later calls and across every element. Cloning per
     * walk keeps documented in-call widening working while scoping it to the
     * call. A single guard for both config paths - the per-call path rebinds
     * the sets in _parseConfig each call, the persistent path restores them
     * from the captured bindings just above - so the two cannot diverge. */
    if (
      _hasHooks('uponSanitizeElement') ||
      _hasHooks('uponSanitizeAttribute')
    ) {
      ALLOWED_TAGS = clone(ALLOWED_TAGS);
    }

    if (_hasHooks('uponSanitizeAttribute')) {
      ALLOWED_ATTR = clone(ALLOWED_ATTR);
    }

    /* Clean up removed elements */
    DOMPurify.removed = [];

    /* Check if dirty is correctly typed for IN_PLACE */
    if (typeof dirty === 'string') {
      IN_PLACE = false;
    }

    if (IN_PLACE) {
      /* Pre-flight the root through _isClobbered. The iterator-driven
         removal path can not detach a parent-less root: _forceRemove
         falls back to setting outerHTML, which is a no-op on a node with
         no parent. A clobbered root would then survive the main loop with
         its attributes uninspected, because the loop skips
         _sanitizeAttributes for nodes _sanitizeElements removed. The
         result would be an attacker-controlled element, complete with any
         event-handler attributes the caller passed in, handed back to the
         application unsanitized. Refuse to sanitize such a root.
         GHSA-r47g-fvhr-h676. The element check reads nodeType through the
         cached getter rather than using `instanceof Element`, which is
         realm-bound and let a clobbered root of a foreign realm skip this
         pre-flight. GHSA-hpcv-96wg-7vj8. */
      if (_getNodeType(dirty) === 1 && _isClobbered(dirty)) {
        throw typeErrorCreate(
          'root node is clobbered and cannot be sanitized in-place'
        );
      }

      /* Snapshot the root's nodes now: the root pre-flight above runs no
         hooks, and everything from the walk on can detach or move nodes
         (hooks, custom-element reactions). See _neutralizeEscapedElements. */
      inPlaceNodes = _collectLiveNodes(dirty);
    } else if (dirty instanceof Node) {
      /* If dirty is a DOM element, append to an empty document to avoid
         elements being stripped by the parser */
      body = _initDocument('<!-->');
      importedNode = body.ownerDocument.importNode(dirty, true);
      if (importedNode.nodeType === 1 && importedNode.nodeName === 'BODY') {
        /* Node is already a body, use as is */
        body = importedNode;
      } else if (importedNode.nodeName === 'HTML') {
        body = importedNode;
      } else {
        // eslint-disable-next-line unicorn/prefer-node-append
        body.appendChild(importedNode);
      }
    } else {
      /* Exit directly if we have nothing to do */
      if (
        !RETURN_DOM &&
        !SAFE_FOR_TEMPLATES &&
        !WHOLE_DOCUMENT &&
        // eslint-disable-next-line unicorn/prefer-includes
        dirty.indexOf('<') === -1
      ) {
        return trustedTypesPolicy && RETURN_TRUSTED_TYPE
          ? trustedTypesPolicy.createHTML(dirty)
          : dirty;
      }

      /* Initialize the document to work on */
      body = _initDocument(dirty);

      /* Check we have a DOM node from the data */
      if (!body) {
        return RETURN_DOM ? null : emptyHTML;
      }
    }

    /* Remove first element node (ours) if FORCE_BODY is set */
    if (body && FORCE_BODY) {
      _forceRemove(body.firstChild);
    }

    /* Get node iterator */
    const walkRoot = IN_PLACE ? dirty : body;
    const nodeIterator = _createIterator(walkRoot);

    /* Now start iterating over the created document */
    try {
      while ((currentNode = nodeIterator.nextNode())) {
        /* Fix IE's strange behavior with manipulated textNodes #89 */
        if (currentNode.nodeType === 3 && currentNode === oldNode) {
          continue;
        }

        /* Sanitize tags and elements */
        if (_sanitizeElements(currentNode, walkRoot)) {
          continue;
        }

        const parentNode = getParentNode(currentNode);

        /* Set the nesting depth of an element */
        if (currentNode.nodeType === 1) {
          if (parentNode && parentNode.__depth) {
            /*
              We want the depth of the node in the original tree, which can
              change when it's removed from its parent.
            */
            currentNode.__depth =
              (currentNode.__removalCount || 0) + parentNode.__depth + 1;
          } else {
            currentNode.__depth = 1;
          }
        }

        /*
         * Remove an element if nested too deeply to avoid mXSS
         * or if the __depth might have been tampered with
         */
        if (
          currentNode.__depth >= MAX_NESTING_DEPTH ||
          numberIsNaN(currentNode.__depth) ||
          (currentNode.nodeType === 1 && _isDepthTampered(currentNode))
        ) {
          _forceRemove(currentNode);
        }

        /* Shadow DOM detected, sanitize it. Realm-safe check
           (GHSA-hpcv-96wg-7vj8): nodeType-based detection instead of
           instanceof, so <template>.content of a foreign realm is walked. */
        if (_isDocumentFragment(currentNode.content)) {
          currentNode.content.__depth = currentNode.__depth;
          _sanitizeShadowDOM(currentNode.content);
        }

        /* Check attributes, sanitize if necessary */
        _sanitizeAttributes(currentNode);

        oldNode = currentNode;
      }
    } catch (error) {
      /* A hook (or a custom-element reaction) threw mid-walk. On the
         IN_PLACE path, anything that already left the root by then (a
         subtree a hook detached or moved out, or one DOMPurify removed)
         is never handed back but may still carry a queued resource
         handler: defuse it before the error propagates.
         GHSA-mrv2-3pqr-j5jr */
      if (IN_PLACE) {
        _neutralizeEscapedElements(dirty, inPlaceNodes);
      }

      throw error;
    }

    oldNode = null;

    /* If we sanitized `dirty` in-place, return it. */
    if (IN_PLACE) {
      /* The in-place ROOT may itself have been force-removed during the walk
         (a rawtext root killed by the SAFE_FOR_XML raw text probe, a
         noscript/noembed root, a disallowed root, an mXSS-canary root, ...).
         Such a root is detached (or, without a parent, could not be detached
         at all), its attributes were never inspected because the walk skips
         _sanitizeAttributes for removed nodes, and for a rawtext element its
         text still carries a literal `</tag>`-bearing payload, so
         re-serialising and re-parsing the returned node re-opens the markup.
         There is no safe node to hand back: cancel the attribute axis on the
         refused root and fail closed - identical in spirit to the
         clobbered-root throw at the IN_PLACE entry. Covers every present and
         future root-kill reason in one check. GHSA-6688-9rhm-gjv2 */
      let rootWasRemoved = false;
      arrayForEach(DOMPurify.removed, (entry) => {
        if (entry.element === dirty) {
          rootWasRemoved = true;
        }
      });

      /* The inline neutralize in _sanitizeElements only covers a hook
         detaching the node it was called for. Also defuse every element
         that left the root by any other route during the call - a hook
         removing an ancestor or a not-yet-visited sibling, a hook moving a
         subtree out, a page custom element's reaction - which the walk
         could no longer reach. Before the root-removed throw, so that exit
         is covered too. GHSA-mrv2-3pqr-j5jr */
      _neutralizeEscapedElements(dirty, inPlaceNodes);

      if (rootWasRemoved) {
        _neutralizeSubtree(dirty);
        throw typeErrorCreate(
          'a node selected for removal could not be safely returned; ' +
            'refusing to sanitize in place'
        );
      }

      return dirty;
    }

    /* Return sanitized string or DOM */
    if (RETURN_DOM) {
      /* Sanitize final DOM template-safe, template expressions can be split
         across several text nodes and survive the per-node pass */
      if (SAFE_FOR_TEMPLATES) {
        body.normalize();
        let html = body.innerHTML;
        arrayForEach([MUSTACHE_EXPR, ERB_EXPR], (expr) => {
          html = stringReplace(html, expr, ' ');
        });
        body.innerHTML = trustedTypesPolicy
          ? trustedTypesPolicy.createHTML(html)
          : html;
      }

      if (RETURN_DOM_FRAGMENT) {
        returnNode = createDocumentFragment.call(body.ownerDocument);

        while (body.firstChild) {
          // eslint-disable-next-line unicorn/prefer-node-append
          returnNode.appendChild(body.firstChild);
        }
      } else {
        returnNode = body;
      }

      if (RETURN_DOM_IMPORT) {
        /*
          AdoptNode() is not used because internal state is not reset
          (e.g. the past names map of a HTMLFormElement), this is safe
          in theory but we would rather not risk another attack vector.
          The state that is cloned by importNode() is explicitly defined
          by the specs.
        */
        returnNode = importNode.call(originalDocument, returnNode, true);
      }

      return returnNode;
    }

    let serializedHTML = WHOLE_DOCUMENT ? body.outerHTML : body.innerHTML;

    /* Sanitize final string template-safe */
    if (SAFE_FOR_TEMPLATES) {
      serializedHTML = stringReplace(serializedHTML, MUSTACHE_EXPR, ' ');
      serializedHTML = stringReplace(serializedHTML, ERB_EXPR, ' ');
    }

    return trustedTypesPolicy && RETURN_TRUSTED_TYPE
      ? trustedTypesPolicy.createHTML(serializedHTML)
      : serializedHTML;
  };

  /**
   * Public method to set the configuration once
   * setConfig
   *
   * @param {Object} cfg configuration object
   */
  DOMPurify.setConfig = function (cfg) {
    _parseConfig(cfg);
    SET_CONFIG = true;
    PRISTINE_ALLOWED_TAGS = ALLOWED_TAGS;
    PRISTINE_ALLOWED_ATTR = ALLOWED_ATTR;
  };

  /**
   * Public method to remove the configuration
   * clearConfig
   *
   */
  DOMPurify.clearConfig = function () {
    CONFIG = null;
    SET_CONFIG = false;
    PRISTINE_ALLOWED_TAGS = null;
    PRISTINE_ALLOWED_ATTR = null;
  };

  /**
   * Public method to check if an attribute value is valid.
   * Uses last set config, if any. Otherwise, uses config defaults.
   * isValidAttribute
   *
   * @param  {string} tag Tag name of containing element.
   * @param  {string} attr Attribute name.
   * @param  {string} value Attribute value.
   * @return {Boolean} Returns true if `value` is valid. Otherwise, returns false.
   */
  DOMPurify.isValidAttribute = function (tag, attr, value) {
    /* Initialize shared config vars if necessary. */
    if (!CONFIG) {
      _parseConfig({});
    }

    const lcTag = stringToLowerCase(tag);
    const lcName = stringToLowerCase(attr);
    return _isValidAttribute(lcTag, lcName, value);
  };

  /**
   * AddHook
   * Public method to add DOMPurify hooks
   *
   * @param {String} entryPoint entry point for the hook to add
   * @param {Function} hookFunction function to execute
   */
  DOMPurify.addHook = function (entryPoint, hookFunction) {
    if (typeof hookFunction !== 'function') {
      return;
    }

    /* Reject unknown entry points. Without this, a non-hook key (e.g.
     * '__proto__') indexes off the prototype chain rather than a real
     * hook array, and arrayPush then writes to Object.prototype. Guard
     * by matching against the known hook names. */
    if (!_isValidHookEntryPoint(entryPoint)) {
      return;
    }

    hooks[entryPoint] = hooks[entryPoint] || [];
    arrayPush(hooks[entryPoint], hookFunction);
  };

  /**
   * RemoveHook
   * Public method to remove a DOMPurify hook at a given entryPoint
   * (pops it from the stack of hooks if more are present)
   *
   * @param {String} entryPoint entry point for the hook to remove
   */
  DOMPurify.removeHook = function (entryPoint) {
    if (!_isValidHookEntryPoint(entryPoint)) {
      return;
    }

    if (hooks[entryPoint]) {
      arrayPop(hooks[entryPoint]);
    }
  };

  /**
   * RemoveHooks
   * Public method to remove all DOMPurify hooks at a given entryPoint
   *
   * @param  {String} entryPoint entry point for the hooks to remove
   */
  DOMPurify.removeHooks = function (entryPoint) {
    if (!_isValidHookEntryPoint(entryPoint)) {
      return;
    }

    if (hooks[entryPoint]) {
      hooks[entryPoint] = [];
    }
  };

  /**
   * RemoveAllHooks
   * Public method to remove all DOMPurify hooks
   *
   */
  DOMPurify.removeAllHooks = function () {
    hooks = {};
  };

  return DOMPurify;
}

export default createDOMPurify();
