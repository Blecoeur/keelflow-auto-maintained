import {
    removeInvalidImageMarkdown,
    convertRequireToImport,
    COMMONJS_REQUIRE_REGEX,
    IMPORT_EXTRACTION_REGEX,
    executeJavaScriptCode,
    getBaseClasses,
    serializeQueryParams,
    handleErrorMessage,
    getNodeModulesPackagePath,
    getInputVariables,
    transformBracesWithColon,
    getEnvironmentVariable,
    getEncryptionKeyPath,
    decryptCredentialData,
    getCredentialData,
    defaultChain,
    getCredentialParam,
    handleEscapeCharacters,
    getUserHome,
    getPlatformDataDir,
    getDataDir,
    mapChatMessageToBaseMessage,
    convertChatHistoryToText,
    serializeChatHistory,
    convertSchemaToZod,
    flattenObject,
    convertBaseMessagetoIMessage,
    convertMultiOptionsToStringArray,
    getVars,
    prepareSandboxVars,
    getVersion,
    mapExtToInputField,
    mapMimeTypeToInputField,
    mapMimeTypeToExt,
    isAllowedUploadMimeType,
    extractOutputFromArray,
    resolveFlowObjValue,
    handleDocumentLoaderOutput,
    parseDocumentLoaderMetadata,
    handleDocumentLoaderMetadata,
    handleDocumentLoaderDocuments,
    normalizeSpecialChars,
    normalizeKeysRecursively,
    stripHTMLFromToolInput,
    processTemplateVariables,
    parseJsonBody,
    parseWithTypeConversion,
    configureStructuredOutput,
    createZodSchemaFromJSON,
    extractResponseContent,
    isReasoningModelOpenAI,
    isZodSchema,
    toolSchemaToJsonSchema
} from './utils'
import { z } from 'zod/v3'
import { AES } from 'crypto-js'
import { HumanMessage, AIMessage, SystemMessage } from '@langchain/core/messages'

describe('removeInvalidImageMarkdown', () => {
    describe('strips non-http/https image markdown', () => {
        it('removes a relative-path image', () => {
            expect(removeInvalidImageMarkdown('![alt](./image.png)')).toBe('')
        })

        it('removes an image with no URL scheme', () => {
            expect(removeInvalidImageMarkdown('![alt](image.png)')).toBe('')
        })

        it('removes a data-URI image', () => {
            expect(removeInvalidImageMarkdown('![alt](data:image/png;base64,abc123)')).toBe('')
        })

        it('removes an image with an absolute local path', () => {
            expect(removeInvalidImageMarkdown('![alt](/some/local/path.png)')).toBe('')
        })
    })

    describe('preserves http and https image markdown', () => {
        it('keeps an https image', () => {
            const input = '![alt](https://example.com/img.png)'
            expect(removeInvalidImageMarkdown(input)).toBe(input)
        })

        it('keeps an http image', () => {
            const input = '![alt](http://example.com/img.png)'
            expect(removeInvalidImageMarkdown(input)).toBe(input)
        })
    })

    describe('non-string inputs pass through unchanged', () => {
        it('returns null as-is', () => {
            expect(removeInvalidImageMarkdown(null as any)).toBeNull()
        })

        it('returns a number as-is', () => {
            expect(removeInvalidImageMarkdown(42 as any)).toBe(42)
        })

        it('returns an object as-is', () => {
            const obj = { a: 1 }
            expect(removeInvalidImageMarkdown(obj as any)).toBe(obj)
        })

        it('returns undefined as-is', () => {
            expect(removeInvalidImageMarkdown(undefined as any)).toBeUndefined()
        })
    })

    describe('mixed content in the same string', () => {
        it('strips relative image but keeps https image', () => {
            const input = 'See ![a](./a.png) and ![b](https://example.com/b.png)'
            expect(removeInvalidImageMarkdown(input)).toBe('See  and ![b](https://example.com/b.png)')
        })

        it('strips multiple non-http images', () => {
            const input = '![x](x.png) text ![y](y.png)'
            expect(removeInvalidImageMarkdown(input)).toBe(' text ')
        })

        it('preserves surrounding text', () => {
            expect(removeInvalidImageMarkdown('before ![alt](./img.png) after')).toBe('before  after')
        })
    })

    describe('edge cases', () => {
        it('handles empty string', () => {
            expect(removeInvalidImageMarkdown('')).toBe('')
        })

        it('handles string with no images', () => {
            expect(removeInvalidImageMarkdown('just text')).toBe('just text')
        })

        it('does not remove a link that is not an image (missing !)', () => {
            expect(removeInvalidImageMarkdown('[alt](./image.png)')).toBe('[alt](./image.png)')
        })
    })
})

// ---------------------------------------------------------------------------
// convertRequireToImport  (line 1459)
// ---------------------------------------------------------------------------

describe('convertRequireToImport', () => {
    describe('default require → default import', () => {
        it('converts const default require', () => {
            expect(convertRequireToImport("const foo = require('bar')")).toBe("import foo from 'bar';")
        })

        it('converts let default require', () => {
            expect(convertRequireToImport("let foo = require('bar')")).toBe("import foo from 'bar';")
        })

        it('converts var default require', () => {
            expect(convertRequireToImport("var foo = require('bar')")).toBe("import foo from 'bar';")
        })

        it('handles scoped package names', () => {
            expect(convertRequireToImport("const pkg = require('@scope/pkg')")).toBe("import pkg from '@scope/pkg';")
        })
    })

    describe('destructured require → named import', () => {
        it('converts single destructured require', () => {
            expect(convertRequireToImport("const { a } = require('bar')")).toBe("import { a } from 'bar';")
        })

        it('converts multiple destructured require', () => {
            expect(convertRequireToImport("const { a, b } = require('bar')")).toBe("import { a, b } from 'bar';")
        })

        it('trims outer whitespace from destructured vars', () => {
            // Leading/trailing spaces around the var list are trimmed; internal spacing preserved
            expect(convertRequireToImport("const {  a, b  } = require('bar')")).toBe("import { a, b } from 'bar';")
        })
    })

    describe('property-access require', () => {
        it('matches as a default import (default pattern takes precedence; .property is not captured)', () => {
            // The default-require pattern at line 1452 has no end-of-string anchor, so it matches
            // `require('bar')` as a prefix of `require('bar').baz`. The property branch is never reached.
            expect(convertRequireToImport("const foo = require('bar').baz")).toBe("import foo from 'bar';")
        })
    })

    describe('indentation preservation', () => {
        it('preserves leading spaces', () => {
            expect(convertRequireToImport("  const foo = require('bar')")).toBe("  import foo from 'bar';")
        })

        it('preserves leading tab', () => {
            expect(convertRequireToImport("\tconst foo = require('bar')")).toBe("\timport foo from 'bar';")
        })
    })

    describe('unrecognised input returns null', () => {
        it('returns null for a console.log call', () => {
            expect(convertRequireToImport("console.log('hello')")).toBeNull()
        })

        it('returns null when require is not called', () => {
            expect(convertRequireToImport("var x = someOtherFunction('y')")).toBeNull()
        })

        it('returns null for an empty string', () => {
            expect(convertRequireToImport('')).toBeNull()
        })
    })
})

// ---------------------------------------------------------------------------
// CommonJS detection regex  (inline at utils.ts line 1579)
// Tests the pattern used to identify require() lines in executeJavaScriptCode
// ---------------------------------------------------------------------------

describe('CommonJS detection regex (utils.ts line 1579 pattern)', () => {
    const commonJsDetectionRegex = COMMONJS_REQUIRE_REGEX

    it('matches a const default require', () => {
        expect(commonJsDetectionRegex.test("const foo = require('x')")).toBe(true)
    })

    it('matches a let default require', () => {
        expect(commonJsDetectionRegex.test("let foo = require('x')")).toBe(true)
    })

    it('matches a destructured require', () => {
        expect(commonJsDetectionRegex.test("const { a } = require('x')")).toBe(true)
    })

    it('does not match a non-require assignment', () => {
        expect(commonJsDetectionRegex.test("const foo = someOtherFn('x')")).toBe(false)
    })

    it('does not match an import statement', () => {
        expect(commonJsDetectionRegex.test("import foo from 'x'")).toBe(false)
    })

    it('does not match a bare require call (no assignment)', () => {
        expect(commonJsDetectionRegex.test("require('x')")).toBe(false)
    })
})

describe('Import extraction regex (utils.ts line 1596 pattern)', () => {
    const extractModules = (code: string): string[] => {
        const results: string[] = []
        const re = new RegExp(IMPORT_EXTRACTION_REGEX.source, 'g')
        let m: RegExpExecArray | null
        while ((m = re.exec(code)) !== null) {
            results.push(m[1] ?? m[2])
        }
        return results
    }

    it('extracts module from a default import', () => {
        expect(extractModules("import foo from 'lodash'")).toEqual(['lodash'])
    })

    it('extracts module from a named import', () => {
        expect(extractModules("import { a, b } from 'react'")).toEqual(['react'])
    })

    it('extracts module from a namespace import', () => {
        expect(extractModules("import * as x from 'mod'")).toEqual(['mod'])
    })

    it('extracts module from a require call', () => {
        expect(extractModules("require('fs')")).toEqual(['fs'])
    })

    it('extracts module from a require call inside an assignment', () => {
        expect(extractModules("const foo = require('path')")).toEqual(['path'])
    })

    it('extracts a scoped package name', () => {
        expect(extractModules("import x from '@scope/pkg'")).toEqual(['@scope/pkg'])
    })

    it('extracts multiple modules from a multi-line code block', () => {
        const code = ["import foo from 'lodash'", "const bar = require('fs')"].join('\n')
        expect(extractModules(code)).toEqual(['lodash', 'fs'])
    })

    it('returns empty array when there are no imports', () => {
        expect(extractModules('console.log("hello")')).toEqual([])
    })
})

// ---------------------------------------------------------------------------
// NodeVM sandbox — availableDependencies allowlist
// ---------------------------------------------------------------------------

describe('NodeVM sandbox — availableDependencies allowlist', () => {
    afterEach(() => {
        delete process.env.ALLOW_BUILTIN_DEP
        delete process.env.TOOL_FUNCTION_EXTERNAL_DEP
    })

    describe('high-risk packages are blocked even when ALLOW_BUILTIN_DEP=true', () => {
        beforeEach(() => {
            process.env.ALLOW_BUILTIN_DEP = 'true'
        })

        const removedPackages = [
            'pg',
            'mysql2',
            'mongodb',
            'ioredis',
            'redis',
            'typeorm',
            'puppeteer',
            'playwright',
            '@zilliz/milvus2-sdk-node'
        ]

        test.each(removedPackages)(
            "require('%s') is denied",
            async (pkg) => {
                await expect(
                    executeJavaScriptCode(`const m = require('${pkg}'); return 'loaded'`, {}, { timeout: 10000 })
                ).rejects.toThrow()
            },
            15000
        )
    })

    it('packages remaining in availableDependencies are still accessible with ALLOW_BUILTIN_DEP=true', async () => {
        process.env.ALLOW_BUILTIN_DEP = 'true'
        const result = await executeJavaScriptCode(`const cheerio = require('cheerio'); return typeof cheerio.load`, {}, { timeout: 10000 })
        expect(result).toBe('function')
    }, 15000)

    it('a removed package becomes accessible via TOOL_FUNCTION_EXTERNAL_DEP', async () => {
        process.env.ALLOW_BUILTIN_DEP = 'true'
        process.env.TOOL_FUNCTION_EXTERNAL_DEP = 'pg'
        const result = await executeJavaScriptCode(`const { Client } = require('pg'); return typeof Client`, {}, { timeout: 10000 })
        expect(result).toBe('function')
    }, 15000)
})

describe('getBaseClasses', () => {
    class A {}
    class B extends A {}
    class C extends B {}

    it('walks the prototype chain and skips BaseLangChain/Serializable', () => {
        expect(getBaseClasses(C)).toEqual(['B', 'A'])
    })

    it('returns an empty list for non-functions', () => {
        expect(getBaseClasses({})).toEqual([])
        expect(getBaseClasses(null)).toEqual([])
    })
})

describe('serializeQueryParams', () => {
    it('serializes primitives with custom encoding', () => {
        expect(serializeQueryParams({ a: 1, b: 'x y' })).toBe('a=1&b=x+y')
    })

    it('serializes arrays with indices by default and without when skipIndex', () => {
        expect(serializeQueryParams({ c: [1, 2] })).toBe('c[0]=1&c[1]=2')
        expect(serializeQueryParams({ c: [1, 2] }, true)).toBe('c=1&c=2')
    })

    it('skips null/undefined and serializes objects and dates', () => {
        const result = serializeQueryParams({ d: null, e: undefined, f: new Date(0) })
        expect(result).toBe('f=1970-01-01T00:00:00.000Z')
    })
})

describe('handleErrorMessage', () => {
    it('uses error.message when present', () => {
        expect(handleErrorMessage(new Error('boom'))).toBe('boom. ')
    })

    it('prefers response.data.error (string or object)', () => {
        expect(handleErrorMessage({ message: 'm', response: { data: { error: 'e' } } })).toBe('m. e. ')
        expect(handleErrorMessage({ message: 'm', response: { data: { error: { code: 1 } } } })).toBe('m. {"code":1}. ')
    })

    it('falls back to msg / Message / raw string data', () => {
        expect(handleErrorMessage({ response: { data: { msg: 'msg1' } } })).toBe('msg1. ')
        expect(handleErrorMessage({ response: { data: { Message: 'msg2' } } })).toBe('msg2. ')
        expect(handleErrorMessage({ response: { data: 'raw' } })).toBe('raw. ')
    })

    it('returns a generic message when nothing is available', () => {
        expect(handleErrorMessage({})).toBe('Unexpected Error.')
    })
})

describe('getNodeModulesPackagePath', () => {
    it('finds installed packages and returns empty for missing ones', () => {
        expect(getNodeModulesPackagePath('lodash')).not.toBe('')
        expect(getNodeModulesPackagePath('definitely-not-a-real-package-xyz-123')).toBe('')
    })
})

describe('getInputVariables', () => {
    it('extracts variable names from double curly braces', () => {
        expect(getInputVariables('Hello {{name}}')).toContain('name')
    })

    it('returns an empty list for non-strings and strings without variables', () => {
        expect(getInputVariables(42 as any)).toEqual([])
        expect(getInputVariables('no vars')).toEqual([])
    })

    it('skips escaped curly brackets', () => {
        expect(getInputVariables('\\{\\{escaped\\}\\}')).toEqual([])
    })

    it('skips paths containing a colon', () => {
        expect(getInputVariables('{{a:b}}')).toEqual([])
    })
})

describe('transformBracesWithColon', () => {
    it('doubles single braces containing a colon', () => {
        expect(transformBracesWithColon('Say { name: x }')).toBe('Say {{ name: x }}')
    })

    it('leaves braces without a colon and already-double braces untouched', () => {
        expect(transformBracesWithColon('{plain}')).toBe('{plain}')
        expect(transformBracesWithColon('{{double}}')).toBe('{{double}}')
    })
})

describe('getEnvironmentVariable', () => {
    it('reads process.env and returns undefined for missing vars', () => {
        process.env.KEELFLOW_TEST_ENV_VAR = 'v1'
        try {
            expect(getEnvironmentVariable('KEELFLOW_TEST_ENV_VAR')).toBe('v1')
        } finally {
            delete process.env.KEELFLOW_TEST_ENV_VAR
        }
        expect(getEnvironmentVariable('KEELFLOW_TEST_ENV_VAR')).toBeUndefined()
    })
})

describe('getEncryptionKeyPath', () => {
    it('honors SECRETKEY_PATH', () => {
        const saved = process.env.SECRETKEY_PATH
        process.env.SECRETKEY_PATH = '/tmp/sk-test'
        try {
            expect(getEncryptionKeyPath()).toBe('/tmp/sk-test/encryption.key')
        } finally {
            if (saved === undefined) delete process.env.SECRETKEY_PATH
            else process.env.SECRETKEY_PATH = saved
        }
    })
})

describe('decryptCredentialData / getCredentialData', () => {
    const ENV_KEY = 'FLOWISE_SECRETKEY_OVERWRITE'
    let saved: string | undefined

    beforeEach(() => {
        saved = process.env[ENV_KEY]
        process.env[ENV_KEY] = 'components-test-key'
    })

    afterEach(() => {
        if (saved === undefined) delete process.env[ENV_KEY]
        else process.env[ENV_KEY] = saved
    })

    it('round-trips AES-encrypted JSON', async () => {
        const encrypted = AES.encrypt(JSON.stringify({ apiKey: 'k1' }), 'components-test-key').toString()
        await expect(decryptCredentialData(encrypted)).resolves.toEqual({ apiKey: 'k1' })
    })

    it('returns an empty object for undecryptable input', async () => {
        await expect(decryptCredentialData('garbage-cipher')).resolves.toEqual({})
    })

    it('throws when the decrypted payload is not JSON', async () => {
        const encrypted = AES.encrypt('not json at all', 'components-test-key').toString()
        await expect(decryptCredentialData(encrypted)).rejects.toThrow('Credentials could not be decrypted.')
    })

    it('getCredentialData returns {} for empty id or missing credential', async () => {
        const options: any = { appDataSource: { getRepository: () => ({ findOneBy: jest.fn() }) }, databaseEntities: { Credential: {} } }
        await expect(getCredentialData('', options)).resolves.toEqual({})
        options.appDataSource.getRepository().findOneBy.mockResolvedValue(null)
        await expect(getCredentialData('cred-1', options)).resolves.toEqual({})
    })

    it('getCredentialData decrypts the stored credential', async () => {
        const encrypted = AES.encrypt(JSON.stringify({ token: 't1' }), 'components-test-key').toString()
        const findOneBy = jest.fn().mockResolvedValue({ id: 'cred-1', encryptedData: encrypted })
        const options: any = {
            appDataSource: { getRepository: () => ({ findOneBy }) },
            databaseEntities: { Credential: {} },
            workspaceId: 'w1'
        }
        await expect(getCredentialData('cred-1', options)).resolves.toEqual({ token: 't1' })
        expect(findOneBy).toHaveBeenCalledWith({ id: 'cred-1', workspaceId: 'w1' })
    })
})

describe('defaultChain / getCredentialParam', () => {
    it('returns the first truthy value', () => {
        expect(defaultChain(0, '', undefined, 'x', 'y')).toBe('x')
        expect(defaultChain(0, false, null)).toBeUndefined()
    })

    it('prioritizes node inputs, then credential data, then default', () => {
        const nodeData: any = { inputs: { a: 'from-input' } }
        expect(getCredentialParam('a', { a: 'from-cred' }, nodeData)).toBe('from-input')
        expect(getCredentialParam('b', { b: 'from-cred' }, nodeData)).toBe('from-cred')
        expect(getCredentialParam('c', {}, nodeData, 'fallback')).toBe('fallback')
        expect(getCredentialParam('d', {}, nodeData)).toBeUndefined()
    })
})

describe('handleEscapeCharacters', () => {
    it('escapes and unescapes special characters in strings', () => {
        expect(handleEscapeCharacters('a\nb\tc', false)).toBe('aFLOWISE_NEWLINEbFLOWISE_TABc')
        expect(handleEscapeCharacters('aFLOWISE_NEWLINEb', true)).toBe('a\nb')
    })

    it('recurses into objects and passes through other types', () => {
        expect(handleEscapeCharacters({ k: 'x\ny' }, false)).toEqual({ k: 'xFLOWISE_NEWLINEy' })
        expect(handleEscapeCharacters(5, false)).toBe(5)
    })
})

describe('path helpers', () => {
    it('getUserHome returns HOME', () => {
        expect(getUserHome()).toBe(process.env.HOME)
    })

    it('getPlatformDataDir points into the platform data folder', () => {
        expect(getPlatformDataDir()).toContain('keelflow')
    })

    it('getDataDir honors KEELFLOW_HOME', () => {
        const saved = process.env.KEELFLOW_HOME
        process.env.KEELFLOW_HOME = '/tmp/keelflow-home-test'
        try {
            expect(getDataDir()).toBe('/tmp/keelflow-home-test')
        } finally {
            if (saved === undefined) delete process.env.KEELFLOW_HOME
            else process.env.KEELFLOW_HOME = saved
        }
    })
})

describe('chat history helpers', () => {
    it('mapChatMessageToBaseMessage maps roles to langchain messages', async () => {
        const result = await mapChatMessageToBaseMessage(
            [
                { role: 'apiMessage', content: 'hi' },
                { role: 'userMessage', content: 'yo' }
            ],
            'org1'
        )
        expect(result[0]._getType()).toBe('ai')
        expect(result[0].content).toBe('hi')
        expect(result[1]._getType()).toBe('human')
        expect(result[1].content).toBe('yo')
    })

    it('mapChatMessageToBaseMessage falls back to text when fileUploads are malformed', async () => {
        const result = await mapChatMessageToBaseMessage([{ role: 'userMessage', content: 'c', fileUploads: '{bad json' }], 'org1')
        expect(result[0]._getType()).toBe('human')
        expect(result[0].content).toBe('c')
    })

    it('convertChatHistoryToText formats roles', () => {
        const text = convertChatHistoryToText([
            { role: 'userMessage', content: 'hi' },
            { role: 'apiMessage', content: 'hello' },
            { role: 'system', content: 'sys' },
            { role: 'userMessage', content: '   ' }
        ] as any)
        expect(text).toBe('Human: hi\nAssistant: hello\nsys')
    })

    it('serializeChatHistory joins arrays and passes strings through', () => {
        expect(serializeChatHistory(['a', 'b'])).toBe('a\nb')
        expect(serializeChatHistory('plain')).toBe('plain')
    })

    it('convertBaseMessagetoIMessage converts langchain messages', () => {
        const result = convertBaseMessagetoIMessage([new HumanMessage('h'), new AIMessage('a'), new SystemMessage('s')])
        expect(result).toEqual([
            { message: 'h', type: 'userMessage' },
            { message: 'a', type: 'apiMessage' },
            { message: 's', type: 'apiMessage' }
        ])
    })
})

describe('convertSchemaToZod', () => {
    it('builds zod schemas from a JSON array schema', () => {
        const zodObj: any = convertSchemaToZod([
            { property: 'name', type: 'string', required: true, description: 'the name' },
            { property: 'age', type: 'number', required: false }
        ])
        expect(zodObj.name.safeParse('a').success).toBe(true)
        expect(zodObj.name.safeParse(5).success).toBe(false)
        expect(zodObj.age.safeParse(1).success).toBe(true)
        expect(zodObj.age.safeParse('x').success).toBe(false)
        expect(zodObj.age.safeParse(undefined).success).toBe(true) // optional
    })

    it('accepts a JSON string and throws on invalid input', () => {
        const zodObj: any = convertSchemaToZod('[{"property":"ok","type":"boolean","required":true}]')
        expect(zodObj.ok.safeParse(true).success).toBe(true)
        expect(zodObj.ok.safeParse('x').success).toBe(false)
        expect(() => convertSchemaToZod('{not json')).toThrow()
    })
})

describe('flattenObject', () => {
    it('flattens nested objects with dot paths', () => {
        expect(flattenObject({ a: { b: 1, c: { d: 2 } }, e: 3 })).toEqual({ 'a.b': 1, 'a.c.d': 2, e: 3 })
    })

    it('returns an empty object for falsy input', () => {
        expect(flattenObject(null as any)).toEqual({})
    })
})

describe('convertMultiOptionsToStringArray', () => {
    it('parses JSON arrays and returns empty on invalid JSON', () => {
        expect(convertMultiOptionsToStringArray('["a","b"]')).toEqual(['a', 'b'])
        expect(convertMultiOptionsToStringArray('nope')).toEqual([])
    })
})

describe('getVars / prepareSandboxVars', () => {
    it('returns [] when workspaceId is missing or variables are skipped', async () => {
        const appDataSource: any = { getRepository: () => ({ findBy: jest.fn() }) }
        await expect(getVars(appDataSource, {} as any, { inputs: {} } as any, {})).resolves.toEqual([])
        await expect(getVars(appDataSource, {} as any, { inputs: {} } as any, { workspaceId: 'w1', skipVariables: true })).resolves.toEqual(
            []
        )
    })

    it('loads variables and applies node-level overrides', async () => {
        const findBy = jest.fn().mockResolvedValue([{ name: 'a', value: '1', type: 'static' }])
        const appDataSource: any = { getRepository: () => ({ findBy }) }
        const nodeData: any = { inputs: { vars: { a: 'overridden', b: 'added' } } }
        const vars = await getVars(appDataSource, { Variable: {} } as any, nodeData, { workspaceId: 'w1' })
        expect(vars).toHaveLength(2)
        expect(vars.find((v: any) => v.name === 'a')).toMatchObject({ value: 'overridden', type: 'static' })
        expect(vars.find((v: any) => v.name === 'b')).toMatchObject({ value: 'added', type: 'static' })
    })

    it('prepareSandboxVars builds a vars object with runtime env resolution', () => {
        process.env.KEELFLOW_SANDBOX_RT = 'rt'
        try {
            const vars = prepareSandboxVars([
                { name: 's', value: 'static-val', type: 'static' },
                { name: 'KEELFLOW_SANDBOX_RT', value: 'ignored', type: 'runtime' }
            ] as any)
            expect(vars).toEqual({ s: 'static-val', KEELFLOW_SANDBOX_RT: 'rt' })
        } finally {
            delete process.env.KEELFLOW_SANDBOX_RT
        }
    })
})

describe('getVersion', () => {
    it('reads the components package version', async () => {
        const pkg = require('../package.json')
        await expect(getVersion()).resolves.toEqual({ version: pkg.version })
    })
})

describe('mime/extension mapping', () => {
    it('mapExtToInputField maps known extensions with txt fallback', () => {
        expect(mapExtToInputField('.pdf')).toBe('pdfFile')
        expect(mapExtToInputField('.csv')).toBe('csvFile')
        expect(mapExtToInputField('.xlsx')).toBe('csvFile')
        expect(mapExtToInputField('.whatever')).toBe('txtFile')
    })

    it('mapMimeTypeToInputField maps known mime types with txt fallback', () => {
        expect(mapMimeTypeToInputField('application/pdf')).toBe('pdfFile')
        expect(mapMimeTypeToInputField('text/csv')).toBe('csvFile')
        expect(mapMimeTypeToInputField('application/msword')).toBe('docxFile')
        expect(mapMimeTypeToInputField('image/png')).toBe('txtFile')
    })

    it('mapMimeTypeToExt maps known mime types and returns empty for unknown', () => {
        expect(mapMimeTypeToExt('text/plain')).toBe('txt')
        expect(mapMimeTypeToExt('application/pdf')).toBe('pdf')
        expect(mapMimeTypeToExt('audio/mpeg')).toBe('mp3')
        expect(mapMimeTypeToExt('application/x-unknown')).toBe('')
    })

    it('isAllowedUploadMimeType requires allowlist membership and an ext mapping', () => {
        expect(isAllowedUploadMimeType('application/pdf')).toBe(true)
        expect(isAllowedUploadMimeType('text/plain')).toBe(true)
        expect(isAllowedUploadMimeType('image/png')).toBe(false)
        expect(isAllowedUploadMimeType('')).toBe(false)
        expect(isAllowedUploadMimeType('   ')).toBe(false)
    })
})

describe('output/document helpers', () => {
    it('extractOutputFromArray handles arrays, objects and primitives', () => {
        expect(extractOutputFromArray([{ text: 'a' }, { text: 'b' }])).toBe('a\nb')
        expect(extractOutputFromArray({ text: 'x' })).toBe('x')
        expect(extractOutputFromArray({ other: 1 })).toBe('{"other":1}')
        expect(extractOutputFromArray('plain')).toBe('plain')
    })

    it('resolveFlowObjValue resolves $flow paths against the source object and recurses', () => {
        expect(resolveFlowObjValue({ a: '$flow.chatId', b: { c: 1 } }, { $flow: { chatId: 'c1' } })).toEqual({ a: 'c1', b: { c: 1 } })
        expect(resolveFlowObjValue('plain', {})).toBe('plain')
    })

    it('handleDocumentLoaderOutput returns docs or escaped joined text', () => {
        const docs: any = [{ pageContent: 'p1' }, { pageContent: 'p2' }]
        expect(handleDocumentLoaderOutput(docs, 'document')).toBe(docs)
        expect(handleDocumentLoaderOutput(docs, 'text')).toBe('p1FLOWISE_NEWLINEp2FLOWISE_NEWLINE')
    })

    it('parseDocumentLoaderMetadata handles empty, string and object metadata', () => {
        expect(parseDocumentLoaderMetadata('')).toEqual({})
        expect(parseDocumentLoaderMetadata('{"a":1}')).toEqual({ a: 1 })
        expect(parseDocumentLoaderMetadata({ a: 1 })).toEqual({ a: 1 })
    })

    it('handleDocumentLoaderMetadata merges and omits metadata keys', () => {
        const docs: any = [{ pageContent: 'p', metadata: { source: 's1', extra: 'e' } }]
        const merged = handleDocumentLoaderMetadata(docs, 'extra', { common: 'c' })
        expect(merged[0].metadata).toEqual({ source: 's1', common: 'c' })

        const starred = handleDocumentLoaderMetadata(docs, '*', { common: 'c' })
        expect(starred[0].metadata).toEqual({ common: 'c' })

        const withSource = handleDocumentLoaderMetadata(docs, '', {}, 'source')
        expect((withSource[0].metadata as any).source).toBe('s1')
    })

    it('handleDocumentLoaderDocuments loads with or without a splitter', async () => {
        const loader: any = { load: jest.fn().mockResolvedValue(['d1']) }
        await expect(handleDocumentLoaderDocuments(loader)).resolves.toEqual(['d1'])
        const splitter: any = { splitDocuments: jest.fn().mockImplementation(async (d: any[]) => [...d, 'd2']) }
        await expect(handleDocumentLoaderDocuments(loader, splitter)).resolves.toEqual(['d1', 'd2'])
        expect(splitter.splitDocuments).toHaveBeenCalledWith(['d1'])
    })
})

describe('normalize helpers', () => {
    it('normalizeSpecialChars replaces non-alphanumerics with underscores', () => {
        expect(normalizeSpecialChars('a b-c.d/e')).toBe('a_b_c_d_e')
    })

    it('normalizeKeysRecursively normalizes keys at all depths', () => {
        expect(normalizeKeysRecursively({ 'a b': { 'c-d': 1 }, arr: [{ 'e f': 2 }] })).toEqual({ a_b: { c_d: 1 }, arr: [{ e_f: 2 }] })
        expect(normalizeKeysRecursively('plain')).toBe('plain')
    })

    it('stripHTMLFromToolInput converts HTML to markdown-ish text', () => {
        expect(stripHTMLFromToolInput('<b>hi</b>')).toContain('hi')
        expect(stripHTMLFromToolInput('plain')).toBe('plain')
    })
})

describe('processTemplateVariables', () => {
    it('replaces {{output}} and JSON-path templates', () => {
        const result = processTemplateVariables({ a: '{{output}}', b: '{{ output.updated }}', c: 'plain' }, '{"updated": 5}')
        expect(result).toEqual({ a: '{"updated": 5}', b: 5, c: 'plain' })
    })

    it('returns the state untouched when empty', () => {
        expect(processTemplateVariables({}, 'x')).toEqual({})
    })

    it('keeps the template when the JSON path is missing', () => {
        const result = processTemplateVariables({ b: '{{ output.missing }}' }, '{"updated": 5}')
        expect(result.b).toBe('{{ output.missing }}')
    })
})

describe('parseJsonBody', () => {
    it('parses strict JSON', () => {
        expect(parseJsonBody('{"a":1}')).toEqual({ a: 1 })
    })

    it('parses JSON5 (unquoted keys, single quotes, trailing commas)', () => {
        expect(parseJsonBody("{a: '1',}")).toEqual({ a: '1' })
    })

    it('throws a descriptive error for unparseable input', () => {
        expect(() => parseJsonBody('not json at all {{{')).toThrow('Invalid JSON format in body')
    })
})

describe('parseWithTypeConversion', () => {
    it('parses valid input directly', async () => {
        const schema = z.object({ name: z.string() })
        await expect(parseWithTypeConversion(schema, { name: 'x' })).resolves.toEqual({ name: 'x' })
    })

    it('converts nested fields: string to number/boolean, number to string', async () => {
        const schema = z.object({ age: z.number(), flag: z.boolean(), label: z.string() })
        await expect(parseWithTypeConversion(schema, { age: '42', flag: 'true', label: 7 })).resolves.toEqual({
            age: 42,
            flag: true,
            label: '7'
        })
    })

    it('does not convert root-level scalars (only nested paths)', async () => {
        await expect(parseWithTypeConversion(z.number(), '5')).rejects.toThrow()
    })

    it('throws when no conversion is possible', async () => {
        const schema = z.object({ age: z.number() })
        await expect(parseWithTypeConversion(schema, { age: 'abc' })).rejects.toThrow()
    })
})

describe('structured output helpers', () => {
    it('configureStructuredOutput wraps the llm with a zod schema', () => {
        const llm: any = { withStructuredOutput: jest.fn().mockReturnValue('wrapped') }
        const result = configureStructuredOutput(llm, [
            { key: 'name', type: 'string', description: 'd' },
            { key: 'tags', type: 'stringArray' },
            { key: 'kind', type: 'enum', enumValues: 'a, b' }
        ])
        expect(result).toBe('wrapped')
        const schema = llm.withStructuredOutput.mock.calls[0][0]
        expect(schema.safeParse({ name: 'n', tags: ['t'], kind: 'a' }).success).toBe(true)
        expect(schema.safeParse({ name: 'n', tags: ['t'], kind: 'z' }).success).toBe(false)
    })

    it('configureStructuredOutput returns the original llm on failure', () => {
        const llm: any = {
            withStructuredOutput: jest.fn().mockImplementation(() => {
                throw new Error('nope')
            })
        }
        expect(configureStructuredOutput(llm, [{ key: 'x', type: 'string' }])).toBe(llm)
    })

    it('createZodSchemaFromJSON builds nested schemas (items is a properties map)', () => {
        const schema = createZodSchemaFromJSON({
            name: { type: 'string', description: 'n' },
            age: { type: 'number' },
            tags: { type: 'array', items: { label: { type: 'string' } } }
        })
        expect(schema.safeParse({ name: 'a', age: 1, tags: [{ label: 'x' }] }).success).toBe(true)
        expect(schema.safeParse({ name: 'a', age: 1, tags: [{ label: 1 }] }).success).toBe(false)
        expect(schema.safeParse({ name: 1, age: 1, tags: [] }).success).toBe(false)
    })
})

describe('extractResponseContent / isReasoningModelOpenAI / toolSchemaToJsonSchema', () => {
    it('extractResponseContent handles all content shapes', () => {
        expect(extractResponseContent(null)).toBe('')
        expect(extractResponseContent({ content: 'str' })).toBe('str')
        expect(extractResponseContent({ content: [{ text: 'a' }, { type: 'text', text: 'b' }, { type: 'reasoning' }] })).toBe('a\nb')
        expect(extractResponseContent({ content: { x: 1 } })).toBe(JSON.stringify({ x: 1 }, null, 2))
        expect(extractResponseContent({ other: 1 })).toBe(JSON.stringify({ other: 1 }, null, 2))
    })

    it('isReasoningModelOpenAI detects reasoning models', () => {
        expect(isReasoningModelOpenAI('o3')).toBe(true)
        expect(isReasoningModelOpenAI('o1-mini')).toBe(true)
        expect(isReasoningModelOpenAI('codex-mini')).toBe(true)
        expect(isReasoningModelOpenAI('gpt-5')).toBe(true)
        expect(isReasoningModelOpenAI('gpt-5-chat')).toBe(false)
        expect(isReasoningModelOpenAI('gpt-4o')).toBe(false)
    })

    it('isZodSchema detects zod schemas', () => {
        expect(isZodSchema(z.string() as any)).toBe(true)
        expect(isZodSchema({})).toBe(false)
        expect(isZodSchema(null)).toBe(false)
    })

    it('toolSchemaToJsonSchema converts zod schemas and strips $schema without mutating plain input', () => {
        expect(toolSchemaToJsonSchema(null)).toEqual({ type: 'object', properties: {} })
        const fromZod = toolSchemaToJsonSchema(z.object({ a: z.string() }))
        expect(fromZod.$schema).toBeUndefined()
        expect((fromZod.properties as any).a).toBeDefined()

        const plain = { type: 'object', $schema: 'http://json-schema.org/draft-07/schema#', properties: { b: {} } }
        const out = toolSchemaToJsonSchema(plain)
        expect(out.$schema).toBeUndefined()
        expect(plain.$schema).toBeDefined() // input not mutated
    })
})
