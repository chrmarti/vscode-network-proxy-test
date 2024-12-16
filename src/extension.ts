/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/// <reference path='vscode-proxy-agent.d.ts' />

import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import * as http2 from 'http2';
import * as net from 'net';
import * as tls from 'tls';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as cp from 'child_process';
import * as dns from 'dns';
import * as util from 'util';
import * as undici from 'undici';
import type * as proxyAgentType from './vscode-proxy-agent';

let proxyLookupResponse: ((url: string, response: string) => Promise<void>) | undefined;

export function activate(context: vscode.ExtensionContext) {

	const agent = (() => {
		try {
			return requireFromApp('vscode-proxy-agent/out/agent');
		} catch {
			return requireFromApp('@vscode/proxy-agent/out/agent');
		}
	})();
	const innerAgent = agent.PacProxyAgent.prototype;
	const callbackName = innerAgent.connect ? 'connect' : 'callback';
	const origCallback = innerAgent[callbackName];
	innerAgent[callbackName] = function (...args: any[]) {
		if (!this.resolverPatched) {
			this.resolverPatched = true;
			const origResolver = this.resolver;
			this.resolver = async (...args: any[]) => {
				const url = args[2];
				const res = await origResolver.apply(this, args);
				if (proxyLookupResponse) {
					await proxyLookupResponse(url, res);
				}
				return res;
			};
		}
		return origCallback.apply(this, args);
	};

	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.test-connection', () => testConnection(false)));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.test-connection-http2', () => testConnection(true)));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.show-os-certificates', () => showOSCertificates()));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.show-builtin-certificates', () => showBuiltInCertificates()));
}

async function testConnection(useHTTP2: boolean) {
	const url = await vscode.window.showInputBox({
		prompt: 'Enter URL to probe',
		value: 'https://example.com',
		ignoreFocusOut: true,
	});
	if (!url) {
		return;
	}

	const editor = await openEmptyEditor();
	await logHeaderInfo(editor);
	await logSettings(editor);
	await logEnvVariables(editor);
	await lookupHosts(editor, url);
	await probeUrl(editor, url, useHTTP2);
}

async function showOSCertificates() {
	const editor = await openEmptyEditor();
	await logHeaderInfo(editor);
	const certs = await readCaCertificates();
	await logCertificates(editor, `Certificates loaded from the OS (${osCertificateLocation()}):`, certs!);
}

function osCertificateLocation() {
	switch (process.platform) {
		case 'win32':
			return 'Manage Computer Certificates > Trusted Root Certification Authorities';
		case 'darwin':
			return `Keychain Access > Certificates > 'Several Keychains'`;
		case 'linux':
			return '/etc/ssl/certs/ca-certificates.crt or ca-bundle.crt';
		default:
			return 'location unknown';
	}
}

async function showBuiltInCertificates() {
	const editor = await openEmptyEditor();
	await logHeaderInfo(editor);
	await logCertificates(editor, 'Certificates built-in with Node.js:', tls.rootCertificates);
}

async function logCertificates(editor: vscode.TextEditor, title: string, certs: ReadonlyArray<string | { from: string[]; pem: string; cert: crypto.X509Certificate }>) {
	await appendText(editor, title);
	for (const cert of certs) {
		const current = typeof cert === 'string' ? tryParseCertificate(cert) : cert instanceof crypto.X509Certificate ? cert : cert.cert;
		if (!(current instanceof crypto.X509Certificate)) {
			await appendText(editor, `- Certificate parse error: ${(current as any)?.message || String(current)}`);
			await appendText(editor, `  Input:\n${cert}`);
			continue;
		}
		// await appendText(editor, `- Raw:\n${typeof cert === 'string' ? cert : cert.pem}`);
		await appendText(editor, `- Subject: ${current.subject.split('\n').join(' ')}${ typeof cert === 'object' && 'from' in cert ? ` (${cert.from.join(' and ')})` : ''}`);
		if (current.subjectAltName) {
			await appendText(editor, `  Subject alt: ${current.subjectAltName}`);
		}
		await appendText(editor, `  Validity: ${current.validFrom} - ${current.validTo}${isPast(current.validTo) ? ' (expired)' : ''}`);
		await appendText(editor, `  Fingerprint: ${current.fingerprint}`);
		await appendText(editor, `  Issuer: ${current.issuer.split('\n').join(' ')}`);
		if (current.keyUsage) {
			await appendText(editor, `  Key usage: ${current.keyUsage.join(', ')}`);
		}
		if (!current.ca) {
			await appendText(editor, `  Not a CA`);
		}
	}
}

async function openEmptyEditor() {
	const document = await vscode.workspace.openTextDocument({ language: 'text' });
	return await vscode.window.showTextDocument(document);
}

async function logHeaderInfo(editor: vscode.TextEditor) {
	await appendText(editor, `Note: Make sure to replace all sensitive information with dummy values before sharing this output.\n`);
	await logRuntimeInfo(editor);
}

async function logRuntimeInfo(editor: vscode.TextEditor) {
	const pkg = require('../package.json');
	const product = require(path.join(vscode.env.appRoot, 'product.json'));
	await appendText(editor, `VS Code ${vscode.version} (${product.commit || 'out-of-source'})`);
	await appendText(editor, `${pkg.displayName} ${pkg.version}`);
	await appendText(editor, `${os.platform()} ${os.release()} ${os.arch()}`);
	if (vscode.env.remoteName) {
		await appendText(editor, `Remote: ${vscode.env.remoteName}`);
	}
	await appendText(editor, ``);
}

async function lookupHosts(editor: vscode.TextEditor, url: string) {
	const host = new URL(url).hostname;
	const timeoutSeconds = 10;
	const dnsLookup = util.promisify(dns.lookup);
	await appendText(editor, `DNS Lookup:`);
	for (const family of [4, 6]) {
		await appendText(editor, `- ipv${family}: `, false);
		const start = Date.now();
		try {
			const dnsResult = await Promise.race([dnsLookup(host, { family }), delay(timeoutSeconds * 1000)]);
			if (dnsResult) {
				await appendText(editor, `${dnsResult.address} (${Date.now() - start} ms)`);
			} else {
				await appendText(editor, `timed out after ${timeoutSeconds} seconds`);
			}
		} catch (err: any) {
			await appendText(editor, `Error (${Date.now() - start} ms): ${err?.message}`);
		}
	}
	await appendText(editor, '');
}

async function probeUrl(editor: vscode.TextEditor, url: string, useHTTP2: boolean) {
	await probeUrlWithNodeModules(editor, url, true, useHTTP2);
	await probeUrlWithFetch(editor, url);
}

async function probeUrlWithNodeModules(editor: vscode.TextEditor, url: string, rejectUnauthorized: boolean, useHTTP2: boolean) {
	await appendText(editor, `Sending${useHTTP2 ? ' HTTP2' : ''} GET request to ${url}${rejectUnauthorized ? '' : ' (allowing unauthorized)'}...`);
	try {
		proxyLookupResponse = async (requestedUrl, response) => {
			if (requestedUrl === url || requestedUrl === url + '/') {
				proxyLookupResponse = undefined;
				await appendText(editor, `vscode-proxy-agent: ${response}`);
			}
		};
		const res = useHTTP2 ? await http2Get(url, rejectUnauthorized) : await httpGet(url, rejectUnauthorized);
		const cert = res.socket instanceof tls.TLSSocket ? (res.socket as tls.TLSSocket).getPeerCertificate(true) : undefined;
		await appendText(editor, `Received response:`);
		await appendText(editor, `- Status: ${res.statusCode} ${res.statusMessage}`);
		if (res.headers.location) {
			await appendText(editor, `- Location: ${res.headers.location}`);
		}
		if (res.statusCode === 407) {
			await appendText(editor, `- Proxy-Authenticate: ${res.headers['proxy-authenticate']}`);
		}
		if (cert) {
			await appendText(editor, `Certificate chain:`);
			let hasExpired = false;
			let current = cert;
			const seen = new Set<string>();
			while (!seen.has(current.fingerprint)) {
				seen.add(current.fingerprint);
				await appendText(editor, `- Subject: ${current.subject?.CN}${current.subject?.O ? ` (${current.subject.O})` : ''}`); // Subject can be undefined? https://github.com/microsoft/vscode-remote-release/issues/9212#issuecomment-1851917503
				if (current.subjectaltname) {
					await appendText(editor, `  Subject alt: ${current.subjectaltname}`);
				}
				const expired = isPast(current.valid_to);
				hasExpired = hasExpired || expired;
				await appendText(editor, `  Validity: ${current.valid_from} - ${current.valid_to}${expired ? ' (expired)' : ''}`);
				await appendText(editor, `  Fingerprint: ${current.fingerprint}`);
				if (current.issuerCertificate) {
					if (current.issuerCertificate.fingerprint512 === current.fingerprint512) {
						await appendText(editor, `  Self-signed`);
					}
					current = current.issuerCertificate;
				} else {
					await appendText(editor, `  Issuer certificate '${current.issuer.CN}${current.issuer.O ? ` (${current.issuer.O})` : ''}' not in certificate chain of the server.`);
				}
			}
			// await appendText(editor, `  Raw:\n${derToPem(cert.raw)}`);
			const uniqCerts = await getAllCaCertificates();
			const toVerify = new crypto.X509Certificate(current.raw);
			const toVerifyPublicKey = toVerify.publicKey.export({ type: 'spki', format: 'der' });
			const localRoots = uniqCerts.filter(({ cert }) => cert.publicKey.export({ type: 'spki', format: 'der' }).equals(toVerifyPublicKey) || toVerify.checkIssued(cert));
			if (localRoots.length) {
				const localRootsUnexpired = localRoots.filter(({ cert }) => !isPast(cert.validTo));
				const allRootsExpired = !localRootsUnexpired.length;
				await logCertificates(editor, `Local root certificates:`, localRoots);
				hasExpired = hasExpired || allRootsExpired;
			} else {
				// https://github.com/microsoft/vscode/issues/177139#issuecomment-1497180563
				await appendText(editor, `\nLast certificate not verified by OS root certificates. This might indicate an issue with the root certificates registered in your OS:`);
				await appendText(editor, `- Make sure that the root certificate for the certificate chain is registered as such in the OS. Use \`F1\` > \`Network Proxy Test: Show OS Certificates\` to see the list loaded by VS Code.`);
				await appendText(editor, `- Also make sure that your proxy and server return the complete certificate chain (except possibly for the root certificate).`);
			}
			if (hasExpired) {
				// https://github.com/microsoft/vscode-remote-release/issues/8207
				await appendText(editor, `\nOne or more certificates have expired. Update the expired certificates in the server's response and in your OS' certificate store (${osCertificateLocation()}).`);
			}
		}
		if (res.statusCode === 407) {
			// https://github.com/microsoft/vscode/issues/179450#issuecomment-1503397566
			await appendText(editor, `\nAuthentication with the proxy server failed. Proxy authentication isn't well supported yet. You could try setting the HTTP Proxy in VS Code's user settings to \`<http|https>://<username>:<password>@<proxy-server>\`. (\`F1\` > \`Preferences: Open User Settings\` > \`HTTP Proxy\`)`);
		}
	} catch (err) {
		await appendText(editor, `Received error: ${(err as any)?.message}${(err as any)?.code ? ` (${(err as any).code})` : ''}`);
		if (rejectUnauthorized && url.startsWith('https:')) {
			await appendText(editor, `Retrying while ignoring certificate issues to collect information on the certificate chain.\n`);
			await probeUrlWithNodeModules(editor, url, false, useHTTP2);
		}
	} finally {
		proxyLookupResponse = undefined;
	}
}

async function probeUrlWithFetch(editor: vscode.TextEditor, url: string) {
	const fetchImpls: { label: string; impl: typeof fetch | undefined }[] = [
		{
			label: 'Electron',
			impl: loadElectronFetch(),
		},
		{
			label: 'Node.js',
			impl: (globalThis as any).__vscodePatchedFetch || globalThis.fetch,
		},
		{
			label: 'Node.js (allow HTTP2)',
			impl: getNodeFetchWithH2(),
		},
	].filter(({ impl }) => !!impl);
	for (const { label, impl } of fetchImpls) {
		await appendText(editor, `\nSending GET request to ${url} using fetch from ${label}...`);
		try {
			const res = await impl!(url, { redirect: 'manual' });
			await appendText(editor, `Received response:`);
			await appendText(editor, `- Status: ${res.status} ${res.statusText}`);
			if (res.headers.has('location')) {
				await appendText(editor, `- Location: ${res.headers.get('location')}`);
			}
			if (res.status === 407) {
				await appendText(editor, `- Proxy-Authenticate: ${res.headers.get('proxy-authenticate')}`);
			}
		} catch (err) {
			await appendText(editor, `Received error: ${(err as any)?.message}${(err as any)?.code ? ` (${(err as any).code})` : ''}`);
		}
	}
}

function loadElectronFetch(): typeof fetch | undefined {
	try {
		return require('electron')?.net?.fetch;
	} catch (err) {
		// Not available.
	}
	return undefined;
}

function getNodeFetchWithH2(): typeof globalThis.fetch {
	const fetch = (globalThis as any).__vscodePatchedFetch || globalThis.fetch;
	return function (input: string | URL | globalThis.Request, init?: RequestInit) {
		return fetch(input, { dispatcher: new undici.Agent({ allowH2: true }), ...init });
	};
}

async function getAllCaCertificates() {
	const osCerts = await readCaCertificates();
	const certMap = new Map<string, { from: string[]; pem: string; cert: crypto.X509Certificate; }>();
	for (const pem of tls.rootCertificates) {
		const cert = tryParseCertificate(pem);
		if (cert instanceof crypto.X509Certificate) {
			certMap.set(cert.fingerprint512, { from: ['built-in'], pem, cert });
		}
	}
	if (osCerts) {
		for (const pem of osCerts) {
			const cert = tryParseCertificate(pem);
			if (cert instanceof crypto.X509Certificate) {
				if (certMap.has(cert.fingerprint512)) {
					certMap.get(cert.fingerprint512)!.from.push('OS');
				} else {
					certMap.set(cert.fingerprint512, { from: ['OS'], pem, cert });
				}
			}
		}
	}
	return [...certMap.values()];
}

function tryParseCertificate(pem: string) {
	try {
		return new crypto.X509Certificate(pem);
	} catch (err) {
		return err;
	}
}

async function httpGet(url: string, rejectUnauthorized: boolean) {
	return await new Promise<http.IncomingMessage>((resolve, reject) => {
		const httpx = url.startsWith('https:') ? https : http;
		const req = httpx.get(url, { rejectUnauthorized }, resolve);
		req.on('error', reject);
	});
}

async function http2Get(url: string, rejectUnauthorized: boolean) {
	return new Promise<{ socket: net.Socket | tls.TLSSocket, headers: NodeJS.Dict<string | string[]>, statusCode: number, statusMessage: string }>(async (resolve, reject) => {
		let socket: net.Socket | tls.TLSSocket;
		const client = http2.connect(url, {
			rejectUnauthorized,
		}, (_session, _socket) => {
			socket = _socket;
		});
		client.on('error', reject);

		const urlObj = new URL(url);
		const req = client.request({
			[http2.constants.HTTP2_HEADER_PATH]: urlObj.pathname,
		});

		req.on('response', (headers, _flags) => {
			const statusCode = headers[':status']!;
			const statusMessage = headers[':status-text'] || http.STATUS_CODES[statusCode] || 'Unknown';
			resolve({ socket, headers, statusCode, statusMessage: Array.isArray(statusMessage) ? statusMessage.join() : statusMessage });
			client.close();
		});
		req.end();
	});
}

const networkSettingsIds = [
	'http.proxy',
	'http.noProxy',
	'http.proxyAuthorization',
	'http.proxyStrictSSL',
	'http.proxySupport',
	'http.electronFetch',
	'http.fetchAdditionalSupport',
	'http.proxyKerberosServicePrincipal',
	'http.systemCertificates',
	'http.experimental.systemCertificatesV2',
];

async function logSettings(editor: vscode.TextEditor) {
	const conf = vscode.workspace.getConfiguration();
	const settings = networkSettingsIds.map(id => {
		const obj = conf.inspect<string>(id);
		const keys = Object.keys(obj || {})
			.filter(key => key !== 'key' && key !== 'defaultValue' && (obj as any)[key] !== undefined);
		return { id, obj, keys };
	}).filter(({ keys }) => keys.length);
	if (settings.length) {
		await appendText(editor, 'Settings:');
		for (const { id, obj, keys } of settings) {
			await appendText(editor, `- ${id}: ${conf.get<string>(id)}`);
			for (const key of keys) {
				await appendText(editor, `  - ${key}: ${(obj as any)[key]}`);
			}
		}
		await appendText(editor, '');
	}
}

async function logEnvVariables(editor: vscode.TextEditor) {
	const envVars = ['http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy'];
	const setEnvVars = [];
	for (const env in process.env) {
		if (envVars.includes(env.toLowerCase())) {
			setEnvVars.push(env);
		}
	}
	if (setEnvVars.length) {
		await appendText(editor, 'Environment variables:');
		for (const env of setEnvVars) {
			await appendText(editor, `${env}=${process.env[env]}`);
		}
		await appendText(editor, '');
	}
}

async function appendText(editor: vscode.TextEditor, string: string, appendEOL = true) {
	await editor.edit(builder => {
		builder.insert(editor.document.lineAt(editor.document.lineCount - 1).range.end, appendEOL ? string + '\n' : string);
	});
}

function requireFromApp(moduleName: string) {
	const appRoot = vscode.env.appRoot;
	try {
		return require(`${appRoot}/node_modules.asar/${moduleName}`);
	} catch (err) {
		// Not in ASAR.
	}
	try {
		return require(`${appRoot}/node_modules/${moduleName}`);
	} catch (err) {
		// Not available.
	}
	throw new Error(`Could not load ${moduleName} from ${appRoot}`);
}

function delay(ms: number) {
	return new Promise<void>(resolve => setTimeout(resolve, ms));
}

// From https://github.com/microsoft/vscode-proxy-agent/blob/4410a426f444c1203142c0b72dd09f63650ba1a4/src/index.ts#L401:

async function readCaCertificates() {

	const proxyAgent = requireFromApp('@vscode/proxy-agent');
	if (proxyAgent.loadSystemCertificates) {
		const agent: typeof proxyAgentType = proxyAgent;
		return agent.loadSystemCertificates({ log: console });
	}

	if (process.platform === 'win32') {
		return readWindowsCaCertificates();
	}
	if (process.platform === 'darwin') {
		return readMacCaCertificates();
	}
	if (process.platform === 'linux') {
		return readLinuxCaCertificates();
	}
	return undefined;
}

async function readWindowsCaCertificates() {
	// @ts-ignore Windows only
	const winCA = (() => {
		try {
			return requireFromApp('vscode-windows-ca-certs');
		} catch {
			return requireFromApp('@vscode/windows-ca-certs');
		}
	})();

	let ders: any[] = [];
	const store = new winCA.Crypt32();
	try {
		let der: any;
		while (der = store.next()) {
			ders.push(der);
		}
	} finally {
		store.done();
	}

	const certs = new Set(ders.map(derToPem));
	return Array.from(certs);
}

async function readMacCaCertificates() {
	const stdout = await new Promise<string>((resolve, reject) => {
		const child = cp.spawn('/usr/bin/security', ['find-certificate', '-a', '-p']);
		const stdout: string[] = [];
		child.stdout.setEncoding('utf8');
		child.stdout.on('data', str => stdout.push(str));
		child.on('error', reject);
		child.on('exit', code => code ? reject(code) : resolve(stdout.join('')));
	});
	const certs = new Set(stdout.split(/(?=-----BEGIN CERTIFICATE-----)/g)
		.filter(pem => !!pem.length));
	return Array.from(certs);
}

const linuxCaCertificatePaths = [
	'/etc/ssl/certs/ca-certificates.crt', // Debian / Ubuntu / Alpine / Fedora
	'/etc/ssl/certs/ca-bundle.crt', // Fedora
	'/etc/ssl/ca-bundle.pem', // OpenSUSE
];

async function readLinuxCaCertificates() {
	for (const certPath of linuxCaCertificatePaths) {
		try {
			const content = await fs.promises.readFile(certPath, { encoding: 'utf8' });
			const certs = new Set(content.split(/(?=-----BEGIN CERTIFICATE-----)/g)
				.filter(pem => !!pem.length));
			return Array.from(certs);
		} catch (err: any) {
			if (err?.code !== 'ENOENT') {
				throw err;
			}
		}
	}
	return [];
}

function derToPem(blob: Buffer) {
	const lines = ['-----BEGIN CERTIFICATE-----'];
	const der = blob.toString('base64');
	for (let i = 0; i < der.length; i += 64) {
		lines.push(der.substr(i, 64));
	}
	lines.push('-----END CERTIFICATE-----', '');
	return lines.join(os.EOL);
}

function isPast(date: string) {
	const parsed = Date.parse(date);
	return !isNaN(parsed) && parsed < Date.now();
}
