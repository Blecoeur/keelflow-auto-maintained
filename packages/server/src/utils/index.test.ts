/**
 * Unit tests for the pure helpers in utils/index.ts.
 * Covers graph construction/traversal, override-config handling, credential
 * redaction, AES encrypt/decrypt round-trips, auth-secret resolution, and the
 * small string/JSON utilities. No database or Express app required.
 */

import fs from 'fs'
import os from 'os'
import path from 'path'

import {
    constructGraphs,
    getStartingNode,
    getStartingNodes,
    getAllConnectedNodes,
    getEndingNodes,
    calculateNodesDepth,
    getAllNodesInPath,
    getFileName,
    saveUpsertFlowData,
    isStartNodeDependOnInput,
    isSameOverrideConfig,
    isSameChatId,
    findAvailableConfigs,
    isFlowValidForStream,
    replaceInputsWithConfig,
    getEncryptionKey,
    encryptCredentialData,
    decryptCredentialData,
    generateEncryptKey,
    generateAuthSecret,
    getAuthSecretsDirectory,
    getOrCreateStoredSecret,
    redactCredentialWithPasswordType,
    transformToCredentialEntity,
    getMemorySessionId,
    findMemoryNode,
    getAllValuesFromJson,
    getTelemetryFlowObj,
    getAppVersion,
    convertToValidFilename,
    aMonthAgo,
    getAPIOverrideConfig,
    getUploadPath,
    generateId,
    getUserHome,
    getNodeModulesPackagePath,
    _removeCredentialId,
    validateHistorySchema,
    REDACTED_CREDENTIAL_VALUE
} from './index'

// keelflow-components resolves to its TS sources, which pull in jsdom and
// ESM-only deps that Jest (CJS) cannot parse. Mock the handful of exports
// utils/index.ts uses, like the other server test files do.
jest.mock('keelflow-components', () => ({
    getInputVariables: (value: any): string[] =>
        typeof value === 'string' ? [...value.matchAll(/\{\{([^{}]+)\}\}/g)].map((m) => m[1]) : [],
    getDataDir: () => process.env.KEELFLOW_HOME || require('path').join(require('os').homedir(), '.keelflow'),
    getEncryptionKeyPath: () => require('path').join(require('os').tmpdir(), 'encryption.key'),
    convertChatHistoryToText: jest.fn(),
    handleEscapeCharacters: (v: any) => v,
    StorageProviderFactory: { getProvider: () => ({ getMulterStorage: () => ({}) }) }
}))

jest.mock('./logger', () => ({
    __esModule: true,
    default: { warn: jest.fn(), info: jest.fn(), error: jest.fn(), debug: jest.fn() }
}))

const node = (id: string, data: any): any => ({ id, data })
const edge = (source: string, target: string): any => ({ source, target })

describe('constructGraphs', () => {
    const nodes = [node('A', {}), node('B', {}), node('C', {})]
    const edges = [edge('A', 'B'), edge('B', 'C')]

    it('builds a directed graph with dependency counts', () => {
        const { graph, nodeDependencies } = constructGraphs(nodes, edges)
        expect(graph).toEqual({ A: ['B'], B: ['C'], C: [] })
        expect(nodeDependencies).toEqual({ A: 0, B: 1, C: 1 })
    })

    it('adds reverse edges when isNonDirected', () => {
        const { graph, nodeDependencies } = constructGraphs(nodes, edges, { isNonDirected: true })
        expect(graph).toEqual({ A: ['B'], B: ['A', 'C'], C: ['B'] })
        expect(nodeDependencies).toEqual({ A: 0, B: 1, C: 1 })
    })

    it('reverses edge direction when isReversed', () => {
        const { graph, nodeDependencies } = constructGraphs(nodes, edges, { isReversed: true })
        expect(graph).toEqual({ A: [], B: ['A'], C: ['B'] })
        expect(nodeDependencies).toEqual({ A: 0, B: 1, C: 1 })
    })

    it('keeps edges whose source is not a known node', () => {
        const { graph } = constructGraphs([node('A', {})], [edge('X', 'A')])
        expect(graph).toEqual({ A: [], X: ['A'] })
    })
})

describe('getStartingNode', () => {
    it('returns node ids with zero dependencies', () => {
        expect(getStartingNode({ A: 0, B: 1, C: 0 })).toEqual({ startingNodeIds: ['A', 'C'] })
    })
})

describe('getStartingNodes', () => {
    it('walks back from the end node and returns depths relative to the farthest start', () => {
        const graph: any = { end: ['mid'], mid: ['start'], start: [] }
        const { startingNodeIds, depthQueue } = getStartingNodes(graph, 'end')
        expect(startingNodeIds).toEqual(['start'])
        expect(depthQueue).toEqual({ start: 0, mid: 1, end: 2 })
    })
})

describe('getAllConnectedNodes', () => {
    it('returns every node reachable from the start node', () => {
        const graph: any = { A: ['B', 'C'], B: ['D'], C: ['D'], D: [] }
        expect(getAllConnectedNodes(graph, 'A')).toEqual(['A', 'B', 'C', 'D'])
    })

    it('handles cycles without looping forever', () => {
        const graph: any = { A: ['B'], B: ['A'] }
        expect(getAllConnectedNodes(graph, 'A').sort()).toEqual(['A', 'B'])
    })
})

describe('getEndingNodes', () => {
    it('treats a single-node graph as its own ending node', () => {
        const ending = node('A', { outputs: { output: 'EndingNode' } })
        const result = getEndingNodes({ A: 0 }, { A: [] }, [ending])
        expect(result).toEqual([ending])
    })

    it('accepts a leaf node from an allowed category', () => {
        const chain = node('B', { category: 'Chains', name: 'llmChain' })
        const result = getEndingNodes({ A: 0, B: 1 }, { A: ['B'], B: [] }, [node('A', {}), chain])
        expect(result).toEqual([chain])
    })

    it('throws when the only leaf node is from a disallowed category', () => {
        const llm = node('B', { category: 'LLMs', name: 'openAI' })
        expect(() => getEndingNodes({ A: 0, B: 1 }, { A: ['B'], B: [] }, [node('A', {}), llm])).toThrow(
            'Ending node must be either a Chain or Agent or Engine'
        )
    })

    it('throws when the ending node has no data', () => {
        const noData = node('B', undefined)
        expect(() => getEndingNodes({ A: 0, B: 1 }, { A: ['B'], B: [] }, [node('A', {}), noData])).toThrow('Ending node B data not found')
    })

    it('throws when there are no ending nodes at all', () => {
        expect(() => getEndingNodes({ A: 0, B: 0 }, { A: [], B: [] }, [node('A', {}), node('B', {})])).toThrow('Ending nodes not found')
    })
})

describe('calculateNodesDepth', () => {
    it('assigns BFS depth from the starting nodes', () => {
        const graph: any = { A: ['B', 'C'], B: ['D'], C: ['D'], D: [], E: [] }
        expect(calculateNodesDepth(graph, ['A'])).toEqual({ A: 0, B: 1, C: 1, D: 2, E: -1 })
    })
})

describe('getAllNodesInPath', () => {
    it('returns all nodes reachable from the start node', () => {
        const graph: any = { A: ['B', 'C'], B: ['D'], C: ['D'], D: [] }
        expect(getAllNodesInPath('A', graph).sort()).toEqual(['A', 'B', 'C', 'D'])
    })
})

describe('getFileName', () => {
    it('returns the plain name after a FILE-STORAGE:: prefix', () => {
        expect(getFileName('FILE-STORAGE::report.pdf')).toBe('report.pdf')
    })

    it('joins JSON arrays after a FILE-STORAGE:: prefix', () => {
        expect(getFileName('FILE-STORAGE::["a.txt","b.txt"]')).toBe('a.txt, b.txt')
    })

    it('extracts filenames from a JSON array of data URIs', () => {
        expect(getFileName('["data:text/plain;base64,notes:hello.txt","data:image/png;base64,img:pic.png"]')).toBe('hello.txt, pic.png')
    })

    it('extracts the filename from a single data URI', () => {
        expect(getFileName('data:text/plain;base64,notes:doc.txt')).toBe('doc.txt')
    })
})

describe('saveUpsertFlowData', () => {
    const nodeData: any = {
        id: 'n1',
        label: 'PDF Loader',
        name: 'pdfLoader',
        category: 'Document Loaders',
        inputs: { file: 'data:application/pdf;base64,file:doc.pdf', skip: '{{question}}', empty: '' },
        inputParams: [
            { name: 'file', label: 'File', type: 'file' },
            { name: 'skip', label: 'Skip', type: 'string' },
            { name: 'empty', label: 'Empty', type: 'string' }
        ]
    }

    it('keeps file params as filenames and skips variable/empty inputs', () => {
        const result = saveUpsertFlowData(nodeData, {})
        expect(result).toHaveLength(1)
        expect(result[0]).toMatchObject({
            label: 'PDF Loader',
            name: 'pdfLoader',
            category: 'Document Loaders',
            id: 'n1',
            paramValues: [{ label: 'File', name: 'file', type: 'file', value: 'doc.pdf' }]
        })
    })

    it('appends to an existing flowData array', () => {
        const result = saveUpsertFlowData(nodeData, { flowData: [{ id: 'existing' }] })
        expect(result).toHaveLength(2)
        expect(result[0]).toEqual({ id: 'existing' })
    })
})

describe('isSameOverrideConfig', () => {
    it('returns true for internal flows with no existing config', () => {
        expect(isSameOverrideConfig(true, undefined, { a: 1 })).toBe(true)
    })

    it('returns false for internal flows with an existing config', () => {
        expect(isSameOverrideConfig(true, { a: 1 }, { a: 1 })).toBe(false)
    })

    it('compares configs by value for API flows', () => {
        expect(isSameOverrideConfig(false, { a: 1 }, { a: 1 })).toBe(true)
        expect(isSameOverrideConfig(false, { a: 1 }, { a: 2 })).toBe(false)
        expect(isSameOverrideConfig(false, undefined, undefined)).toBe(true)
        expect(isSameOverrideConfig(false, { a: 1 }, undefined)).toBe(false)
    })
})

describe('isSameChatId', () => {
    it('compares chat ids', () => {
        expect(isSameChatId('a', 'a')).toBe(true)
        expect(isSameChatId(undefined, undefined)).toBe(true)
        expect(isSameChatId('a', undefined)).toBe(false)
    })
})

describe('findAvailableConfigs', () => {
    const componentCredentials: any = {
        myCred: {
            inputs: [
                { name: 'apiKey', label: 'API Key', type: 'password' },
                { name: 'endpoint', label: 'Endpoint', type: 'url' }
            ]
        }
    }

    it('maps each input param type to an override config entry', () => {
        const flowNode = node('n1', {
            id: 'n1',
            label: 'LLM Chain',
            inputParams: [
                { name: 'model', label: 'Model', type: 'string' },
                { name: 'secret', label: 'Secret', type: 'password' },
                { name: 'file', label: 'File', type: 'file', fileType: 'pdf' },
                { name: 'mode', label: 'Mode', type: 'options', options: [{ name: 'fast' }, { name: 'slow' }] },
                { name: 'cred', label: 'Cred', type: 'credential', credentialNames: ['myCred'] },
                {
                    name: 'items',
                    label: 'Items',
                    type: 'array',
                    array: [
                        { name: 'x', type: 'string' },
                        { name: 'mode', type: 'options', options: [{ name: 'o1' }] },
                        { name: 'f', type: 'file', fileType: 'csv' }
                    ]
                }
            ],
            inputs: {}
        })
        const configs = findAvailableConfigs([flowNode], componentCredentials)
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'Model', name: 'model', type: 'string' })
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'Secret', name: 'secret', type: 'string' })
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'File', name: 'files', type: 'pdf' })
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'Mode', name: 'mode', type: 'fast, slow' })
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'API Key', name: 'apiKey', type: 'string' })
        expect(configs).toContainEqual({ node: 'LLM Chain', nodeId: 'n1', label: 'Endpoint', name: 'endpoint', type: 'url' })
        expect(configs).toContainEqual({
            node: 'LLM Chain',
            nodeId: 'n1',
            label: 'Items',
            name: 'items',
            type: 'array',
            schema: { x: 'string', mode: '(o1)', f: 'csv' }
        })
    })

    it('falls back to "string" for options params without options', () => {
        const flowNode = node('n1', { id: 'n1', label: 'N', inputParams: [{ name: 'mode', label: 'Mode', type: 'options' }], inputs: {} })
        expect(findAvailableConfigs([flowNode], {})).toEqual([{ node: 'N', nodeId: 'n1', label: 'Mode', name: 'mode', type: 'string' }])
    })

    it('builds a JSON schema from loadConfig inputs and strips credential ids', () => {
        const flowNode = node('n1', {
            id: 'n1',
            label: 'Agent',
            inputParams: [{ name: 'cfg', label: 'Cfg', type: 'json', loadConfig: true }],
            inputs: { cfgConfig: '{"a":1,"b":true,"c":[1],"d":{"e":1},"cfg":"x","FLOWISE_CREDENTIAL_ID":"abc"}' }
        })
        const configs = findAvailableConfigs([flowNode], {})
        expect(configs).toEqual([
            {
                node: 'Agent',
                nodeId: 'n1',
                label: 'Cfg Config',
                name: 'cfgConfig',
                type: 'json',
                schema: { a: 'number', b: 'boolean', c: 'array', d: 'object' }
            }
        ])
    })

    it('deduplicates identical configs', () => {
        const mk = (id: string) =>
            node(id, { id, label: 'N', inputParams: [{ name: 'model', label: 'Model', type: 'string' }], inputs: {} })
        expect(findAvailableConfigs([mk('a'), mk('a')], {})).toHaveLength(1)
        // same param on different nodes yields distinct entries (nodeId differs)
        expect(findAvailableConfigs([mk('a'), mk('b')], {})).toHaveLength(2)
    })
})

describe('isFlowValidForStream', () => {
    const chatModel = (inputs: any, name = 'chatOpenAI') => node('cm', { category: 'Chat Models', name, inputs })
    const llmChain: any = { category: 'Chains', name: 'llmChain' }

    it('is valid for a streaming-capable chat model and a streamable chain', () => {
        expect(isFlowValidForStream([chatModel({})], llmChain)).toBe(true)
    })

    it('is invalid when the chat model disables streaming', () => {
        expect(isFlowValidForStream([chatModel({ streaming: false })], llmChain)).toBe(false)
        expect(isFlowValidForStream([chatModel({ streaming: 'false' })], llmChain)).toBe(false)
    })

    it('is invalid for chat models outside the streaming whitelist', () => {
        expect(isFlowValidForStream([chatModel({}, 'unknownModel')], llmChain)).toBe(false)
    })

    it('is invalid for blacklisted chains', () => {
        expect(isFlowValidForStream([chatModel({})], { category: 'Chains', name: 'openApiChain' } as any)).toBe(false)
    })

    it('is valid for whitelisted agents and always for openAIAssistant', () => {
        expect(isFlowValidForStream([chatModel({})], { category: 'Agents', name: 'csvAgent' } as any)).toBe(true)
        expect(isFlowValidForStream([chatModel({})], { category: 'Agents', name: 'otherAgent' } as any)).toBe(false)
        expect(isFlowValidForStream([], { category: 'Agents', name: 'openAIAssistant' } as any)).toBe(true)
    })

    it('is invalid when an output parser is present', () => {
        const parser = node('op', { category: 'Output Parsers', name: 'structuredParser', inputs: {} })
        expect(isFlowValidForStream([chatModel({}), parser], llmChain)).toBe(false)
    })

    it('accepts whitelisted LLMs', () => {
        const llm = node('l', { category: 'LLMs', name: 'openAI', inputs: {} })
        expect(isFlowValidForStream([llm], llmChain)).toBe(true)
    })
})

describe('replaceInputsWithConfig', () => {
    const baseNode = (): any => ({
        id: 'node1',
        name: 'llmChain',
        label: 'LLM Chain',
        inputs: { systemMessagePrompt: 'old', temperature: '0.5', files: ['a'], cfg: { x: 1 } }
    })
    const overridesFor = (...names: string[]): any => ({
        'LLM Chain': names.map((name) => ({ name, enabled: true }))
    })

    it('replaces a string input when the parameter is enabled', () => {
        const result: any = replaceInputsWithConfig(baseNode(), { systemMessagePrompt: 'new' }, overridesFor('systemMessagePrompt'), [])
        expect(result.inputs.systemMessagePrompt).toBe('new')
    })

    it('leaves inputs untouched when the parameter is not enabled', () => {
        const result: any = replaceInputsWithConfig(
            baseNode(),
            { systemMessagePrompt: 'new', temperature: '0.9' },
            overridesFor('systemMessagePrompt'),
            []
        )
        expect(result.inputs.temperature).toBe('0.5')
    })

    it('coerces "true"/"false" override strings to booleans', () => {
        const result: any = replaceInputsWithConfig(baseNode(), { temperature: 'true' }, overridesFor('temperature'), [])
        expect(result.inputs.temperature).toBe(true)
    })

    it('concatenates arrays instead of replacing them', () => {
        const result: any = replaceInputsWithConfig(baseNode(), { files: ['b', 'a'] }, overridesFor('files'), [])
        expect(result.inputs.files).toEqual(['a', 'b'])
    })

    it('merges plain object overrides into existing objects', () => {
        const result: any = replaceInputsWithConfig(baseNode(), { cfg: { y: 2 } }, overridesFor('cfg'), [])
        expect(result.inputs.cfg).toEqual({ x: 1, y: 2 })
    })

    it('applies node-id-scoped object overrides', () => {
        const result: any = replaceInputsWithConfig(
            baseNode(),
            { systemMessagePrompt: { node1: 'scoped' } },
            overridesFor('systemMessagePrompt'),
            []
        )
        expect(result.inputs.systemMessagePrompt).toBe('scoped')
    })

    it('ignores overrides scoped to a different node name', () => {
        const result: any = replaceInputsWithConfig(
            baseNode(),
            { systemMessagePrompt: { llmChain_9: 'other' } },
            overridesFor('systemMessagePrompt'),
            []
        )
        expect(result.inputs.systemMessagePrompt).toBe('old')
    })

    it('filters vars through variableOverrides', () => {
        const result: any = replaceInputsWithConfig(baseNode(), { vars: { v1: 'a', v2: 'b' } }, overridesFor('vars'), [
            { name: 'v1', enabled: true } as any
        ])
        expect(result.inputs.vars).toEqual({ v1: 'a' })
    })

    it('passes analytics through untouched', () => {
        const analytics = { chatflowid: 'cf1' }
        const result: any = replaceInputsWithConfig(baseNode(), { analytics }, {}, [])
        expect(result.inputs.analytics).toEqual(analytics)
    })
})

describe('isStartNodeDependOnInput', () => {
    it('returns true when a starting node is a Cache', () => {
        expect(isStartNodeDependOnInput([node('c', { category: 'Cache', inputs: {} })], [])).toBe(true)
    })

    it('returns true when a starting node input references a variable', () => {
        const start = node('s', { category: 'Chat Models', inputs: { prompt: '{{question}}' } })
        expect(isStartNodeDependOnInput([start], [start])).toBe(true)
    })

    it('returns true when a prompt template uses {{question}}', () => {
        const start = node('s', { category: 'Chat Models', inputs: { model: 'gpt' } })
        const prompt = node('p', {
            category: 'Prompts',
            name: 'chatPromptTemplate',
            inputs: { promptValues: { template: '{{question}}' } }
        })
        expect(isStartNodeDependOnInput([start], [start, prompt])).toBe(true)
    })

    it('returns true for whitelisted node names', () => {
        const start = node('s', { category: 'Chat Models', inputs: { model: 'gpt' } })
        const autoGpt = node('a', { category: 'Agents', name: 'autoGPT', inputs: {} })
        expect(isStartNodeDependOnInput([start], [start, autoGpt])).toBe(true)
    })

    it('returns false for a plain flow', () => {
        const start = node('s', { category: 'Chat Models', inputs: { model: 'gpt' } })
        expect(isStartNodeDependOnInput([start], [start])).toBe(false)
    })
})

describe('getMemorySessionId', () => {
    it('prefers overrideConfig.sessionId for external calls', () => {
        expect(getMemorySessionId(undefined, { overrideConfig: { sessionId: 's1' } } as any, 'chat', false)).toBe('s1')
    })

    it('throws when overrideConfig.sessionId is not a string', () => {
        expect(() => getMemorySessionId(undefined, { overrideConfig: { sessionId: 42 } } as any, 'chat', false)).toThrow(
            'Invalid sessionId: must be a string'
        )
    })

    it('falls back to incoming chatId for external calls', () => {
        expect(getMemorySessionId(undefined, { chatId: 'c9' } as any, 'chat', false)).toBe('c9')
    })

    it('throws when incoming chatId is not a string', () => {
        expect(() => getMemorySessionId(undefined, { chatId: 7 } as any, 'chat', false)).toThrow('Invalid chatId: must be a string')
    })

    it('skips API inputs for internal calls and uses the memory node sessionId', () => {
        const memory = node('m', { category: 'Memory', inputs: { sessionId: 'm1' } })
        expect(getMemorySessionId(memory, { overrideConfig: { sessionId: 'ignored' } } as any, 'chat', true)).toBe('m1')
    })

    it('throws when the memory node sessionId is not a string', () => {
        const memory = node('m', { category: 'Memory', inputs: { sessionId: 3 } })
        expect(() => getMemorySessionId(memory, {} as any, 'chat', true)).toThrow('Invalid sessionId: must be a string')
    })

    it('defaults to the chatId', () => {
        expect(getMemorySessionId(undefined, {} as any, 'chat-1', false)).toBe('chat-1')
    })
})

describe('findMemoryNode', () => {
    it('returns the memory node connected by an edge', () => {
        const memory = node('mem', { id: 'mem', category: 'Memory', inputs: {} })
        const other = node('o', { id: 'o', category: 'Chains', inputs: {} })
        expect(findMemoryNode([memory, other], [edge('mem', 'o')])).toEqual(memory)
    })

    it('returns undefined when no memory node is connected', () => {
        const memory = node('mem', { id: 'mem', category: 'Memory', inputs: {} })
        const other = node('o', { id: 'o', category: 'Chains', inputs: {} })
        expect(findMemoryNode([memory, other], [edge('o', 'mem')])).toBeUndefined()
        expect(findMemoryNode([other], [])).toBeUndefined()
    })
})

describe('crypto helpers', () => {
    const ENV_KEY = 'FLOWISE_SECRETKEY_OVERWRITE'
    let saved: string | undefined

    beforeEach(() => {
        saved = process.env[ENV_KEY]
        process.env[ENV_KEY] = 'unit-test-secret-key'
    })

    afterEach(() => {
        if (saved === undefined) delete process.env[ENV_KEY]
        else process.env[ENV_KEY] = saved
    })

    it('generateEncryptKey returns 24 random bytes as base64', () => {
        const key = generateEncryptKey()
        expect(Buffer.from(key, 'base64')).toHaveLength(24)
        expect(generateEncryptKey()).not.toBe(key)
    })

    it('generateAuthSecret returns 32 random bytes as base64', () => {
        const secret = generateAuthSecret()
        expect(Buffer.from(secret, 'base64')).toHaveLength(32)
        expect(generateAuthSecret()).not.toBe(secret)
    })

    it('getEncryptionKey prefers the env overwrite', async () => {
        await expect(getEncryptionKey()).resolves.toBe('unit-test-secret-key')
    })

    it('encrypt/decrypt round-trips credential data', async () => {
        const encrypted = await encryptCredentialData({ apiKey: 'sk-123', nested: { a: 1 } })
        expect(encrypted).not.toContain('sk-123')
        await expect(decryptCredentialData(encrypted)).resolves.toEqual({ apiKey: 'sk-123', nested: { a: 1 } })
    })

    it('redacts password fields when decrypting with credential metadata', async () => {
        const creds: any = { myCred: { inputs: [{ name: 'apiKey', type: 'password' }] } }
        const encrypted = await encryptCredentialData({ apiKey: 'sk-123' })
        await expect(decryptCredentialData(encrypted, 'myCred', creds)).resolves.toEqual({ apiKey: REDACTED_CREDENTIAL_VALUE })
    })

    it('returns an empty object for undecryptable input', async () => {
        await expect(decryptCredentialData('not-a-valid-cipher-text')).resolves.toEqual({})
    })
})

describe('redactCredentialWithPasswordType', () => {
    const creds: any = {
        myCred: {
            inputs: [
                { name: 'apiKey', type: 'password' },
                { name: 'url', type: 'url' },
                { name: 'user', type: 'string' }
            ]
        }
    }

    it('redacts password fields and masks URL passwords, leaving others intact', () => {
        const result = redactCredentialWithPasswordType(
            'myCred',
            { apiKey: 'secret', url: 'https://user:pass@example.com/x', user: 'bob' },
            creds
        )
        expect(result.apiKey).toBe(REDACTED_CREDENTIAL_VALUE)
        expect(result.url).toContain('••••••')
        expect(result.url).not.toContain('pass')
        expect(result.user).toBe('bob')
    })

    it('keeps URLs without a password as-is', () => {
        const result = redactCredentialWithPasswordType('myCred', { url: 'https://example.com/x' }, creds)
        expect(result.url).toBe('https://example.com/x')
    })

    it('does not mutate the input object', () => {
        const input = { apiKey: 'secret' }
        redactCredentialWithPasswordType('myCred', input, creds)
        expect(input.apiKey).toBe('secret')
    })
})

describe('transformToCredentialEntity', () => {
    const ENV_KEY = 'FLOWISE_SECRETKEY_OVERWRITE'
    let saved: string | undefined

    beforeEach(() => {
        saved = process.env[ENV_KEY]
        process.env[ENV_KEY] = 'unit-test-secret-key'
    })

    afterEach(() => {
        if (saved === undefined) delete process.env[ENV_KEY]
        else process.env[ENV_KEY] = saved
    })

    it('encrypts plainDataObj and copies name/credentialName/workspaceId', async () => {
        const entity = await transformToCredentialEntity({
            name: 'My Cred',
            credentialName: 'openai',
            plainDataObj: { apiKey: 'sk-abc' },
            workspaceId: 'w1'
        } as any)
        expect(entity.name).toBe('My Cred')
        expect(entity.credentialName).toBe('openai')
        expect(entity.workspaceId).toBe('w1')
        expect(typeof (entity as any).encryptedData).toBe('string')
        expect((entity as any).encryptedData).not.toContain('sk-abc')
    })

    it('leaves encryptedData unset when no plainDataObj is given', async () => {
        const entity = await transformToCredentialEntity({ name: 'N', credentialName: 'c' } as any)
        expect((entity as any).encryptedData).toBeUndefined()
    })
})

describe('getOrCreateStoredSecret (file-based)', () => {
    let tmpDir: string
    let savedPath: string | undefined
    const ENV_KEY = 'KEELFLOW_TEST_AUTH_SECRET'

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keelflow-secret-'))
        savedPath = process.env.SECRETKEY_PATH
        process.env.SECRETKEY_PATH = tmpDir
        delete process.env[ENV_KEY]
    })

    afterEach(() => {
        if (savedPath === undefined) delete process.env.SECRETKEY_PATH
        else process.env.SECRETKEY_PATH = savedPath
        delete process.env[ENV_KEY]
        fs.rmSync(tmpDir, { recursive: true, force: true })
    })

    it('prefers a set env var (trimmed)', async () => {
        process.env[ENV_KEY] = '  env-value  '
        await expect(getOrCreateStoredSecret({ envKey: ENV_KEY, fileName: 's.txt', awsSecretIdSuffix: 'Test' })).resolves.toBe('env-value')
    })

    it('treats the weak default as unset', async () => {
        process.env[ENV_KEY] = 'weak'
        const value = await getOrCreateStoredSecret({
            envKey: ENV_KEY,
            fileName: 's.txt',
            awsSecretIdSuffix: 'Test',
            weakDefault: 'weak'
        })
        expect(value).not.toBe('weak')
        expect(Buffer.from(value, 'base64')).toHaveLength(32)
    })

    it('generates, persists and re-reads a secret file', async () => {
        const options = { envKey: ENV_KEY, fileName: 'secret.txt', awsSecretIdSuffix: 'Test' }
        const first = await getOrCreateStoredSecret(options)
        expect(fs.readFileSync(path.join(tmpDir, 'secret.txt'), 'utf8')).toBe(first)
        const second = await getOrCreateStoredSecret(options)
        expect(second).toBe(first)
    })

    it('uses defaultValueForNew when generating', async () => {
        const value = await getOrCreateStoredSecret({
            envKey: ENV_KEY,
            fileName: 'issuer.txt',
            awsSecretIdSuffix: 'Issuer',
            defaultValueForNew: 'flowise'
        })
        expect(value).toBe('flowise')
        expect(fs.readFileSync(path.join(tmpDir, 'issuer.txt'), 'utf8')).toBe('flowise')
    })

    it('reads an existing secret file', async () => {
        fs.writeFileSync(path.join(tmpDir, 'existing.txt'), 'stored-value')
        await expect(getOrCreateStoredSecret({ envKey: ENV_KEY, fileName: 'existing.txt', awsSecretIdSuffix: 'Existing' })).resolves.toBe(
            'stored-value'
        )
    })
})

describe('misc helpers', () => {
    it('getAllValuesFromJson flattens nested objects and arrays', () => {
        const values = getAllValuesFromJson({ a: 1, b: { c: '{{question}}', d: [true, null] } })
        expect(values).toHaveLength(4)
        expect(values).toContain('{{question}}')
        expect(values).toContain(1)
    })

    it('getTelemetryFlowObj keeps only ids and edge endpoints', () => {
        const nodes = [node('1', { secret: 'x' }), node('2', {})]
        const edges = [edge('1', '2')]
        expect(getTelemetryFlowObj(nodes, edges)).toEqual({ nodes: ['1', '2'], edges: [{ source: '1', target: '2' }] })
    })

    it('getAppVersion reads the server package version', async () => {
        await expect(getAppVersion()).resolves.toBe('3.2.1')
    })

    it('convertToValidFilename strips invalid characters and lowercases', () => {
        expect(convertToValidFilename('Hello World')).toBe('helloworld')
        expect(convertToValidFilename('Report:Final?.pdf')).toBe('reportfinal .pdf')
    })

    it('aMonthAgo returns a date roughly one month in the past', () => {
        const d = aMonthAgo()
        const ageMs = Date.now() - d.getTime()
        expect(ageMs).toBeGreaterThan(25 * 24 * 3600 * 1000)
        expect(ageMs).toBeLessThan(32 * 24 * 3600 * 1000)
    })

    it('generateId returns a uuid v4', () => {
        expect(generateId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    })

    it('_removeCredentialId strips FLOWISE_CREDENTIAL_ID recursively', () => {
        const input = {
            a: 1,
            FLOWISE_CREDENTIAL_ID: 'x',
            b: { FLOWISE_CREDENTIAL_ID: 'y', c: 2 },
            arr: [{ FLOWISE_CREDENTIAL_ID: 'z', d: 3 }]
        }
        expect(_removeCredentialId(input)).toEqual({ a: 1, b: { c: 2 }, arr: [{ d: 3 }] })
        expect(_removeCredentialId('plain')).toBe('plain')
        expect(_removeCredentialId(null)).toBeNull()
    })

    it('validateHistorySchema accepts only well-formed history entries', () => {
        expect(validateHistorySchema([])).toBe(true)
        expect(
            validateHistorySchema([
                { role: 'apiMessage', content: 'hi' },
                { role: 'userMessage', content: 'yo' }
            ])
        ).toBe(true)
        expect(validateHistorySchema([{ role: 'user', content: 'hi' }])).toBe(false)
        expect(validateHistorySchema([{ role: 'apiMessage' }])).toBe(false)
        expect(validateHistorySchema([null])).toBe(false)
        expect(validateHistorySchema('nope' as any)).toBe(false)
    })
})

describe('getAPIOverrideConfig', () => {
    it('parses a valid apiConfig', () => {
        const chatflow: any = {
            apiConfig: JSON.stringify({ overrideConfig: { status: true, nodes: { a: 1 }, variables: [{ name: 'v' }] } })
        }
        expect(getAPIOverrideConfig(chatflow)).toEqual({
            nodeOverrides: { a: 1 },
            variableOverrides: [{ name: 'v' }],
            apiOverrideStatus: true
        })
    })

    it('returns defaults when apiConfig is missing or invalid', () => {
        expect(getAPIOverrideConfig({} as any)).toEqual({ nodeOverrides: {}, variableOverrides: [], apiOverrideStatus: false })
        expect(getAPIOverrideConfig({ apiConfig: '{not json' } as any)).toEqual({
            nodeOverrides: {},
            variableOverrides: [],
            apiOverrideStatus: false
        })
    })
})

describe('path helpers', () => {
    it('getUserHome returns HOME and falls back to cwd', () => {
        expect(getUserHome()).toBe(process.env.HOME)
        const savedHome = process.env.HOME
        delete process.env.HOME
        try {
            expect(getUserHome()).toBe(process.cwd())
        } finally {
            process.env.HOME = savedHome
        }
    })

    it('getUserHome uses USERPROFILE on win32', () => {
        const original = Object.getOwnPropertyDescriptor(process, 'platform')
        Object.defineProperty(process, 'platform', { value: 'win32' })
        process.env.USERPROFILE = 'C:\\Users\\test'
        try {
            expect(getUserHome()).toBe('C:\\Users\\test')
        } finally {
            if (original) Object.defineProperty(process, 'platform', original)
            delete process.env.USERPROFILE
        }
    })

    it('getNodeModulesPackagePath finds installed packages and returns empty for missing ones', () => {
        expect(getNodeModulesPackagePath('lodash')).not.toBe('')
        expect(fs.existsSync(getNodeModulesPackagePath('lodash'))).toBe(true)
        expect(getNodeModulesPackagePath('definitely-not-a-real-package-xyz-123')).toBe('')
    })

    it('getUploadPath honors BLOB_STORAGE_PATH', () => {
        const saved = process.env.BLOB_STORAGE_PATH
        process.env.BLOB_STORAGE_PATH = '/tmp/blob-test'
        try {
            expect(getUploadPath()).toBe(path.join('/tmp/blob-test', 'uploads'))
        } finally {
            if (saved === undefined) delete process.env.BLOB_STORAGE_PATH
            else process.env.BLOB_STORAGE_PATH = saved
        }
    })

    it('getUploadPath defaults to a uploads folder under the data dir', () => {
        const saved = process.env.BLOB_STORAGE_PATH
        delete process.env.BLOB_STORAGE_PATH
        try {
            expect(getUploadPath().endsWith(path.join('uploads'))).toBe(true)
        } finally {
            if (saved !== undefined) process.env.BLOB_STORAGE_PATH = saved
        }
    })

    it('getAuthSecretsDirectory honors SECRETKEY_PATH', () => {
        const saved = process.env.SECRETKEY_PATH
        process.env.SECRETKEY_PATH = '/tmp/secrets-test'
        try {
            expect(getAuthSecretsDirectory()).toBe('/tmp/secrets-test')
        } finally {
            if (saved === undefined) delete process.env.SECRETKEY_PATH
            else process.env.SECRETKEY_PATH = saved
        }
    })
})
