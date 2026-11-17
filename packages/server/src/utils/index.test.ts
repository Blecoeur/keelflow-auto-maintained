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
    getGlobalVariable,
    getVariableValue,
    resolveVariables,
    clearSessionMemory,
    getSessionChatHistory,
    buildFlow,
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
// utils/index.ts uses, like the other server test files do. handleEscapeCharacters
// and convertChatHistoryToText replicate the real implementations so variable
// resolution can be tested faithfully.
jest.mock('keelflow-components', () => {
    const jsonEscapeCharacters = [
        { escape: '"', value: 'FLOWISE_DOUBLE_QUOTE' },
        { escape: '\n', value: 'FLOWISE_NEWLINE' },
        { escape: '\b', value: 'FLOWISE_BACKSPACE' },
        { escape: '\f', value: 'FLOWISE_FORM_FEED' },
        { escape: '\r', value: 'FLOWISE_CARRIAGE_RETURN' },
        { escape: '\t', value: 'FLOWISE_TAB' },
        { escape: '\\', value: 'FLOWISE_BACKSLASH' }
    ]
    const handleEscapesJSONParse = (input: string, reverse: boolean): string => {
        for (const el of jsonEscapeCharacters) {
            input = reverse ? input.replaceAll(el.value, el.escape) : input.replaceAll(el.escape, el.value)
        }
        return input
    }
    const iterateEscapesJSONParse = (input: any, reverse: boolean): any => {
        for (const key in input) {
            const t = typeof input[key]
            if (t === 'string') input[key] = handleEscapesJSONParse(input[key], reverse)
            else if (t === 'object') input[key] = iterateEscapesJSONParse(input[key], reverse)
        }
        return input
    }
    return {
        getInputVariables: (value: any): string[] =>
            typeof value === 'string' ? [...value.matchAll(/\{\{([^{}]+)\}\}/g)].map((m) => m[1]) : [],
        handleEscapeCharacters: (input: any, reverse: boolean): any => {
            const t = typeof input
            if (t === 'string') return handleEscapesJSONParse(input, reverse)
            if (t === 'object') return iterateEscapesJSONParse(input, reverse)
            return input
        },
        convertChatHistoryToText: (chatHistory: any[] = []): string =>
            chatHistory
                .map((m) => {
                    if (!m) return ''
                    const content = 'message' in m ? m.message : m.content
                    if (!content || content.trim() === '') return ''
                    const type = 'type' in m ? m.type : m.role
                    if (type === 'apiMessage' || type === 'assistant') return `Assistant: ${content}`
                    if (type === 'userMessage' || type === 'user') return `Human: ${content}`
                    return `${content}`
                })
                .filter((m) => m !== '')
                .join('\n'),
        getDataDir: () => process.env.KEELFLOW_HOME || require('path').join(require('os').homedir(), '.keelflow'),
        getEncryptionKeyPath: () => process.env.KEELFLOW_TEST_KEY_PATH || require('path').join(require('os').tmpdir(), 'encryption.key'),
        StorageProviderFactory: { getProvider: () => ({ getMulterStorage: () => ({}) }) }
    }
})

// Mock the AWS SDK so the SECRETKEY_STORAGE_TYPE=aws branches can be exercised
// without network access. The send behavior is controlled per test via __mockSend.
jest.mock('@aws-sdk/client-secrets-manager', () => {
    const mockSend = jest.fn()
    return {
        SecretsManagerClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
        GetSecretValueCommand: jest.fn().mockImplementation((input: any) => ({ input })),
        CreateSecretCommand: jest.fn().mockImplementation((input: any) => ({ input })),
        __mockSend: mockSend
    }
})

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

describe('getGlobalVariable', () => {
    it('builds a vars object from static variables', async () => {
        const vars = await getGlobalVariable(undefined, [{ name: 'a', value: '1', type: 'static' } as any])
        expect(vars).toEqual({ a: '1' })
    })

    it('reads runtime variables from process.env', async () => {
        process.env.KEELFLOW_TEST_RUNTIME_VAR = 'rt-value'
        try {
            const vars = await getGlobalVariable(undefined, [
                { name: 'KEELFLOW_TEST_RUNTIME_VAR', value: 'ignored', type: 'runtime' } as any
            ])
            expect(vars).toEqual({ KEELFLOW_TEST_RUNTIME_VAR: 'rt-value' })
        } finally {
            delete process.env.KEELFLOW_TEST_RUNTIME_VAR
        }
    })

    it('returns an empty string for a missing runtime env var', async () => {
        delete process.env.KEELFLOW_MISSING_VAR
        const vars = await getGlobalVariable(undefined, [{ name: 'KEELFLOW_MISSING_VAR', value: 'x', type: 'runtime' } as any])
        expect(vars).toEqual({ KEELFLOW_MISSING_VAR: '' })
    })

    it('applies enabled var overrides and adds unknown vars', async () => {
        const available: any[] = [{ name: 'a', value: '1', type: 'static' }]
        const vars = await getGlobalVariable({ vars: { a: 'overridden', b: 'new' } }, available, [
            { name: 'a', enabled: true },
            { name: 'b', enabled: true }
        ] as any)
        expect(vars).toEqual({ a: 'overridden', b: 'new' })
        expect(available[0].type).toBe('static')
        expect(available[0].value).toBe('overridden')
    })

    it('skips overrides that are not enabled', async () => {
        const vars = await getGlobalVariable({ vars: { a: 'nope' } }, [{ name: 'a', value: '1', type: 'static' } as any], [
            { name: 'a', enabled: false }
        ] as any)
        expect(vars).toEqual({ a: '1' })
    })
})

describe('getVariableValue', () => {
    it('returns plain strings unchanged', async () => {
        await expect(getVariableValue('hello', [], '', [], false)).resolves.toBe('hello')
    })

    it('round-trips object params through JSON', async () => {
        await expect(getVariableValue({ a: 1 }, [], '', [], false)).resolves.toEqual({ a: 1 })
    })

    it('resolves {{question}} when the param accepts variables, escaping special chars', async () => {
        await expect(getVariableValue('Q: {{question}}', [], 'what?\nnow', [], true)).resolves.toBe('Q: what?FLOWISE_NEWLINEnow')
    })

    it('leaves {{question}} untouched when the param does not accept variables', async () => {
        await expect(getVariableValue('Q: {{question}}', [], 'what?', [], false)).resolves.toBe('Q: {{question}}')
    })

    it('resolves {{chat_history}} from chat history', async () => {
        const history: any = [
            { role: 'userMessage', content: 'hi' },
            { role: 'apiMessage', content: 'hello' }
        ]
        await expect(getVariableValue('{{chat_history}}', [], '', history, true)).resolves.toBe('Human: hiFLOWISE_NEWLINEAssistant: hello')
    })

    it('resolves {{file_attachment}} from uploaded files content', async () => {
        await expect(getVariableValue('{{file_attachment}}', [], '', [], true, undefined, 'file-content')).resolves.toBe('file-content')
    })

    it('resolves $vars from available variables', async () => {
        const vars: any = [{ name: 'apiKey', value: 'secret', type: 'static' }]
        await expect(getVariableValue('key={{$vars.apiKey}}', [], '', [], false, undefined, undefined, vars)).resolves.toBe('key=secret')
    })

    it('applies $vars overrides from flowConfig', async () => {
        const flowConfig: any = { vars: { apiKey: 'overridden' } }
        const vars: any = [{ name: 'apiKey', value: 'secret', type: 'static' }]
        await expect(
            getVariableValue('{{$vars.apiKey}}', [], '', [], false, flowConfig, undefined, vars, [{ name: 'apiKey', enabled: true }] as any)
        ).resolves.toBe('overridden')
    })

    it('resolves $flow paths from flowConfig', async () => {
        await expect(getVariableValue('id={{$flow.chatflowid}}', [], '', [], false, { chatflowid: 'cf-1' })).resolves.toBe('id=cf-1')
    })

    it('resolves node instance references', async () => {
        const nodes = [node('n1', { instance: 'hello' })]
        await expect(getVariableValue('{{n1.data.instance}}', nodes, '', [], false)).resolves.toBe('hello')
    })

    it('substitutes node instance references inside a larger string when accepted', async () => {
        const nodes = [node('n1', { instance: 'world' })]
        await expect(getVariableValue('hello {{n1.data.instance}}!', nodes, '', [], true)).resolves.toBe('hello world!')
    })

    it('resolves nested keys of object instances', async () => {
        const nodes = [node('n1', { instance: { key: 'nested-value' } })]
        await expect(getVariableValue('{{n1.data.instance.key}}', nodes, '', [], false)).resolves.toBe('nested-value')
    })

    it('parses JSON-string instances before resolving nested keys', async () => {
        const nodes = [node('n1', { instance: '{"key":"json-value"}' })]
        await expect(getVariableValue('{{n1.data.instance.key}}', nodes, '', [], false)).resolves.toBe('json-value')
    })

    it('reduces agentflow instances to their id when accepted', async () => {
        const nodes = [node('n1', { instance: { predecessorAgents: ['x'], id: 'ag-1', other: 1 } })]
        await expect(getVariableValue('agent: {{n1.data.instance}}', nodes, '', [], true)).resolves.toBe('agent: {\\"id\\":\\"ag-1\\"}')
    })
})

describe('resolveVariables', () => {
    it('resolves variables in node inputs, including array elements', async () => {
        const nodes = [node('n1', { instance: 'world' })]
        const nodeData: any = {
            id: 'n2',
            inputParams: [
                { name: 'prompt', acceptVariable: true },
                { name: 'list', acceptVariable: false }
            ],
            inputs: { prompt: 'hello {{n1.data.instance}}', list: ['{{n1.data.instance}}', 'plain'] }
        }
        const result: any = await resolveVariables(nodeData, nodes, 'q', [])
        expect(result.inputs.prompt).toBe('hello world')
        expect(result.inputs.list).toEqual(['world', 'plain'])
    })

    it('does not mutate the original node data', async () => {
        const nodes = [node('n1', { instance: 'world' })]
        const nodeData: any = {
            id: 'n2',
            inputParams: [{ name: 'prompt', acceptVariable: true }],
            inputs: { prompt: '{{n1.data.instance}}' }
        }
        await resolveVariables(nodeData, nodes, 'q', [])
        expect(nodeData.inputs.prompt).toBe('{{n1.data.instance}}')
    })
})

describe('getEncryptionKey file fallback', () => {
    const ENV_KEY = 'FLOWISE_SECRETKEY_OVERWRITE'
    const KEY_PATH_ENV = 'KEELFLOW_TEST_KEY_PATH'
    let tmpDir: string
    let savedEnv: string | undefined
    let savedKeyPath: string | undefined
    let savedSecretPath: string | undefined

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keelflow-key-'))
        savedEnv = process.env[ENV_KEY]
        delete process.env[ENV_KEY]
        savedKeyPath = process.env[KEY_PATH_ENV]
        process.env[KEY_PATH_ENV] = path.join(tmpDir, 'encryption.key')
        savedSecretPath = process.env.SECRETKEY_PATH
        process.env.SECRETKEY_PATH = tmpDir
    })

    afterEach(() => {
        if (savedEnv === undefined) delete process.env[ENV_KEY]
        else process.env[ENV_KEY] = savedEnv
        if (savedKeyPath === undefined) delete process.env[KEY_PATH_ENV]
        else process.env[KEY_PATH_ENV] = savedKeyPath
        if (savedSecretPath === undefined) delete process.env.SECRETKEY_PATH
        else process.env.SECRETKEY_PATH = savedSecretPath
        fs.rmSync(tmpDir, { recursive: true, force: true })
    })

    it('reads the key from the key file when present', async () => {
        fs.writeFileSync(path.join(tmpDir, 'encryption.key'), 'file-based-key')
        await expect(getEncryptionKey()).resolves.toBe('file-based-key')
    })

    it('generates and persists a key when the key file is missing', async () => {
        const key = await getEncryptionKey()
        expect(Buffer.from(key, 'base64')).toHaveLength(24)
        expect(fs.readFileSync(path.join(tmpDir, 'encryption.key'), 'utf8')).toBe(key)
    })
})

describe('clearSessionMemory / getSessionChatHistory (node fixtures)', () => {
    let tmpDir: string
    let fixturePath: string

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keelflow-node-'))
        fixturePath = path.join(tmpDir, 'fakeMemory.js')
        fs.writeFileSync(
            fixturePath,
            [
                'class nodeClass {',
                '    async init(data, prev, options) { this.data = data; return this }',
                '    async clearChatMessages(...args) { (globalThis.__clearCalls = globalThis.__clearCalls || []).push(args[args.length - 1]) }',
                '    async getChatMessages(sessionId, _, prepend) { return [{ role: "userMessage", content: "msg-" + sessionId }, ...(prepend || [])] }',
                '}',
                'module.exports = { nodeClass }'
            ].join('\n')
        )
        ;(globalThis as any).__clearCalls = []
    })

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true })
        delete (globalThis as any).__clearCalls
    })

    const componentNodes = (): any => ({ fakeMemory: { filePath: fixturePath } })
    const clearCalls = (): any[] => (globalThis as any).__clearCalls

    it('clears memory by chatId and sets inputs.sessionId', async () => {
        const memory = node('mem', { id: 'mem', name: 'fakeMemory', category: 'Memory', inputs: {} })
        await clearSessionMemory([memory], componentNodes(), 'chat-1', {} as any)
        expect(clearCalls()).toEqual(['chat-1'])
        expect(memory.data.inputs.sessionId).toBe('chat-1')
    })

    it('sessionId takes priority over chatId', async () => {
        const memory = node('mem', { id: 'mem', name: 'fakeMemory', category: 'Memory', inputs: {} })
        await clearSessionMemory([memory], componentNodes(), 'chat-1', {} as any, undefined, 'session-9')
        expect(clearCalls()).toEqual(['session-9'])
    })

    it('OpenAIAssistant nodes are cleared via threadId/chatId options', async () => {
        const assistant = node('a', { id: 'a', name: 'fakeMemory', category: 'Agents', type: 'OpenAIAssistant', inputs: {} })
        await clearSessionMemory([assistant], componentNodes(), 'chat-1', {} as any, undefined, 'thread-1')
        expect(clearCalls()).toEqual([{ type: 'threadId', id: 'thread-1' }])
        await clearSessionMemory([assistant], componentNodes(), 'chat-2', {} as any)
        expect(clearCalls()).toEqual([
            { type: 'threadId', id: 'thread-1' },
            { type: 'chatId', id: 'chat-2' }
        ])
    })

    it('skips nodes that are not memory/assistant, and honors the view-message-dialog filter', async () => {
        const chain = node('c', { id: 'c', name: 'fakeMemory', category: 'Chains', inputs: {} })
        await clearSessionMemory([chain], componentNodes(), 'chat-1', {} as any)
        expect(clearCalls()).toEqual([])

        const memory = node('mem', { id: 'mem', name: 'fakeMemory', category: 'Memory', label: 'Buffer Memory', inputs: {} })
        await clearSessionMemory([memory], componentNodes(), 'chat-1', {} as any, undefined, undefined, 'Other Memory', 'true')
        expect(clearCalls()).toEqual([])
        await clearSessionMemory([memory], componentNodes(), 'chat-1', {} as any, undefined, undefined, 'Buffer Memory', 'true')
        expect(clearCalls()).toEqual(['chat-1'])
    })

    it('getSessionChatHistory returns messages and rewrites the memory sessionId', async () => {
        const memory = node('mem', { id: 'mem', name: 'fakeMemory', category: 'Memory', inputs: { sessionId: 'old' } })
        const messages = await getSessionChatHistory('cf-1', 'sess-1', memory, componentNodes(), {} as any, {} as any, {} as any, [
            { role: 'apiMessage', content: 'prepended' } as any
        ])
        expect(memory.data.inputs.sessionId).toBe('sess-1')
        expect(messages).toEqual([
            { role: 'userMessage', content: 'msg-sess-1' },
            { role: 'apiMessage', content: 'prepended' }
        ])
    })
})

describe('AWS Secrets Manager mode', () => {
    const ENV = 'SECRETKEY_STORAGE_TYPE'
    let saved: string | undefined

    beforeEach(() => {
        saved = process.env[ENV]
    })

    afterEach(() => {
        if (saved === undefined) delete process.env[ENV]
        else process.env[ENV] = saved
    })

    // Re-import utils/index.ts with SECRETKEY_STORAGE_TYPE=aws so the module-level
    // USE_AWS_SECRETS_MANAGER flag flips on; the AWS SDK is mocked above.
    const loadWithAws = async () => {
        jest.resetModules()
        process.env[ENV] = 'aws'
        const sdk = require('@aws-sdk/client-secrets-manager')
        const mod = await import('./index')
        return { mod, mockSend: sdk.__mockSend as jest.Mock }
    }

    it('getEncryptionKey reads from AWS and creates the secret on ResourceNotFound', async () => {
        const { mod, mockSend } = await loadWithAws()
        try {
            mockSend.mockResolvedValue({ SecretString: 'aws-key' })
            await expect(mod.getEncryptionKey()).resolves.toBe('aws-key')

            const err: any = new Error('not found')
            err.name = 'ResourceNotFoundException'
            mockSend.mockRejectedValueOnce(err)
            const key = await mod.getEncryptionKey()
            expect(Buffer.from(key, 'base64')).toHaveLength(24)
        } finally {
            delete process.env[ENV]
        }
    })

    it('decryptCredentialData fetches FlowiseCredential_ secrets from AWS', async () => {
        const { mod, mockSend } = await loadWithAws()
        try {
            mockSend.mockResolvedValue({ SecretString: JSON.stringify({ apiKey: 'k' }) })
            await expect(mod.decryptCredentialData('FlowiseCredential_abc')).resolves.toEqual({ apiKey: 'k' })
        } finally {
            delete process.env[ENV]
        }
    })

    it('decryptCredentialData wraps AWS errors', async () => {
        const { mod, mockSend } = await loadWithAws()
        try {
            const err: any = new Error('boom')
            err.name = 'AccessDeniedException'
            mockSend.mockRejectedValue(err)
            await expect(mod.decryptCredentialData('FlowiseCredential_abc')).rejects.toThrow('Failed to decrypt credential data.')
        } finally {
            delete process.env[ENV]
        }
    })

    it('getOrCreateStoredSecret reads from AWS and creates on miss with defaultValueForNew', async () => {
        const { mod, mockSend } = await loadWithAws()
        delete process.env.KEELFLOW_TEST_AWS_SECRET
        try {
            mockSend.mockResolvedValue({ SecretString: 'aws-secret' })
            await expect(
                mod.getOrCreateStoredSecret({ envKey: 'KEELFLOW_TEST_AWS_SECRET', fileName: 'x.txt', awsSecretIdSuffix: 'Test' })
            ).resolves.toBe('aws-secret')

            const err: any = new Error('not found')
            err.name = 'ResourceNotFoundException'
            mockSend.mockRejectedValueOnce(err)
            await expect(
                mod.getOrCreateStoredSecret({
                    envKey: 'KEELFLOW_TEST_AWS_SECRET',
                    fileName: 'issuer.txt',
                    awsSecretIdSuffix: 'Issuer',
                    defaultValueForNew: 'flowise'
                })
            ).resolves.toBe('flowise')
        } finally {
            delete process.env[ENV]
            delete process.env.KEELFLOW_TEST_AWS_SECRET
        }
    })
})

describe('buildFlow', () => {
    let tmpDir: string
    let fixturePath: string
    let failingFixturePath: string

    const FIXTURE = [
        'class nodeClass {',
        '    constructor() {',
        '        this.vectorStoreMethods = {',
        '            upsert: async (data, options) => {',
        '                (globalThis.__upsertCalls = globalThis.__upsertCalls || []).push({ data, options })',
        "                return 'upsert-result'",
        '            }',
        '        }',
        '    }',
        '    async init(data, question, options) {',
        '        ;(globalThis.__initCalls = globalThis.__initCalls || []).push({ data, question, options })',
        "        if (data.name === 'setVariable') return { dynamicVariables: { foo: 'bar' }, output: 'sv-output' }",
        "        return { output: 'result-' + data.id }",
        '    }',
        '}',
        'module.exports = { nodeClass }'
    ].join('\n')

    const FAILING_FIXTURE = [
        'class nodeClass {',
        '    async init() { throw new Error("init exploded") }',
        '}',
        'module.exports = { nodeClass }'
    ].join('\n')

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keelflow-build-'))
        fixturePath = path.join(tmpDir, 'fakeNode.js')
        failingFixturePath = path.join(tmpDir, 'failNode.js')
        fs.writeFileSync(fixturePath, FIXTURE)
        fs.writeFileSync(failingFixturePath, FAILING_FIXTURE)
        ;(globalThis as any).__initCalls = []
        ;(globalThis as any).__upsertCalls = []
    })

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true })
        delete (globalThis as any).__initCalls
        delete (globalThis as any).__upsertCalls
    })

    const initCalls = (): any[] => (globalThis as any).__initCalls
    const upsertCalls = (): any[] => (globalThis as any).__upsertCalls
    const fakeNode = (id: string, data: any): any =>
        node(id, { id, name: 'fakeNode', label: `Node ${id}`, category: 'Chains', inputs: {}, inputParams: [], ...data })

    const baseParams = (over: any): any => ({
        startingNodeIds: ['A'],
        reactFlowNodes: [],
        reactFlowEdges: [],
        graph: {},
        depthQueue: {},
        componentNodes: { fakeNode: { filePath: fixturePath }, setVariable: { filePath: fixturePath } },
        question: 'q',
        chatHistory: [],
        chatId: 'c1',
        sessionId: 's1',
        chatflowid: 'cf1',
        apiMessageId: '',
        appDataSource: {} as any,
        ...over
    })

    const linearFlow = () => {
        const nodes = [fakeNode('A', { category: 'Chat Models' }), fakeNode('B', {})]
        const edges = [edge('A', 'B')]
        const graph = constructGraphs(nodes, edges).graph
        const depthQueue = calculateNodesDepth(graph, ['A'])
        return { nodes, edges, graph, depthQueue }
    }

    it('initializes nodes in dependency order and stores instances', async () => {
        const { nodes, edges, graph, depthQueue } = linearFlow()
        const result: any[] = await buildFlow(baseParams({ reactFlowNodes: nodes, reactFlowEdges: edges, graph, depthQueue }))
        expect(initCalls().map((c) => c.data.id)).toEqual(['A', 'B'])
        const byId = Object.fromEntries(result.map((n: any) => [n.id, n.data.instance]))
        expect(byId.A).toEqual({ output: 'result-A' })
        expect(byId.B).toEqual({ output: 'result-B' })
    })

    it('upsert mode records flow data and stops at stopNodeId with the upsert result', async () => {
        const { nodes, edges, graph, depthQueue } = linearFlow()
        const result = await buildFlow(
            baseParams({ reactFlowNodes: nodes, reactFlowEdges: edges, graph, depthQueue, isUpsert: true, stopNodeId: 'B' })
        )
        expect(result.result).toBe('upsert-result')
        expect(result.flowData).toHaveLength(2)
        expect(upsertCalls()).toHaveLength(1)
        expect(upsertCalls()[0].data.id).toBe('B')
        // node A was initialized normally, node B was upserted (no init call for B)
        expect(initCalls().map((c) => c.data.id)).toEqual(['A'])
    })

    it('skips document loaders connected to a non-memory vector store', async () => {
        const doc = fakeNode('D', {
            category: 'Document Loaders',
            outputAnchors: [{ id: 'a1', options: [{ name: 'output', id: 'docOut' }] }],
            outputs: { output: 'output' }
        })
        const vs = fakeNode('V', { category: 'Vector Stores' })
        const edges = [{ source: 'D', target: 'V', sourceHandle: 'docOut' } as any]
        const graph = constructGraphs([doc, vs], edges).graph
        const depthQueue = calculateNodesDepth(graph, ['D'])
        await buildFlow(baseParams({ startingNodeIds: ['D'], reactFlowNodes: [doc, vs], reactFlowEdges: edges, graph, depthQueue }))
        expect(initCalls().map((c) => c.data.id)).toEqual(['V'])
    })

    it('collects dynamic variables from setVariable nodes for downstream nodes', async () => {
        const nodes = [fakeNode('A', { name: 'setVariable', category: 'Utilities' }), fakeNode('B', {})]
        const edges = [edge('A', 'B')]
        const graph = constructGraphs(nodes, edges).graph
        const depthQueue = calculateNodesDepth(graph, ['A'])
        const result: any[] = await buildFlow(baseParams({ reactFlowNodes: nodes, reactFlowEdges: edges, graph, depthQueue }))
        expect(initCalls()[1].options.dynamicVariables).toEqual({ foo: 'bar' })
        expect(result.find((n: any) => n.id === 'A').data.instance).toBe('sv-output')
    })

    it('rethrows node init errors', async () => {
        const nodes = [node('A', { id: 'A', name: 'failNode', label: 'Fail', category: 'Chains', inputs: {}, inputParams: [] })]
        const graph = constructGraphs(nodes, []).graph
        const depthQueue = calculateNodesDepth(graph, ['A'])
        await expect(
            buildFlow(
                baseParams({
                    reactFlowNodes: nodes,
                    reactFlowEdges: [],
                    graph,
                    depthQueue,
                    componentNodes: { failNode: { filePath: failingFixturePath } }
                })
            )
        ).rejects.toThrow()
    })
})
