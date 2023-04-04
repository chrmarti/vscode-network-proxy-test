/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import * as tls from 'tls';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as cp from 'child_process';

let proxyLookupResponse: ((url: string, response: string) => Promise<void>) | undefined;

export function activate(context: vscode.ExtensionContext) {

	const agent = (() => {
		try {
			return requireFromApp('vscode-proxy-agent/out/agent');
		} catch {
			return requireFromApp('@vscode/proxy-agent/out/agent');
		}
	})();
	const origCallback = agent.PacProxyAgent.prototype.callback;
	agent.PacProxyAgent.prototype.callback = function (...args: any[]) {
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

	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.test-connection', () => testConnection(true)));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.test-connection-allow-unauthorized', () => testConnection(false)));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.show-os-certificates', () => showOSCertificates()));
	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.show-builtin-certificates', () => showBuiltInCertificates()));
}

async function testConnection(rejectUnauthorized: boolean) {
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
	proxyLookupResponse = async (requestedUrl, response) => {
		if (requestedUrl === url || requestedUrl === url + '/') {
			proxyLookupResponse = undefined;
			await appendText(editor, `vscode-proxy-agent: ${response}`);
		}
	};
	await probeUrl(editor, url, rejectUnauthorized);
	proxyLookupResponse = undefined;
}

async function showOSCertificates() {
	const editor = await openEmptyEditor();
	await logHeaderInfo(editor);
	const certs = await readCaCertificates();
	await logCertificates(editor, `Certificates loaded from the OS (${osCertificateLocation()}):`, certs!.certs);
}

function osCertificateLocation() {
	switch (process.platform) {
		case 'win32':
			return 'Manage Computer Certificates > Trusted Root Certification Authorities';
		case 'darwin':
			return 'Keychain Access > Certificates';
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

async function logCertificates(editor: vscode.TextEditor, title: string, certs: ReadonlyArray<string>) {
	await appendText(editor, title);
	for (const cert of certs) {
		const current = new crypto.X509Certificate(cert);
		await appendText(editor, `- Subject: ${current.subject.split('\n').join(' ')}`);
		if (current.subjectAltName) {
			await appendText(editor, `  Subject alt: ${current.subjectAltName}`);
		}
		await appendText(editor, `  Validity: ${current.validFrom} - ${current.validTo}`);
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
	await appendText(editor, ``);
}

async function probeUrl(editor: vscode.TextEditor, url: string, rejectUnauthorized: boolean) {
	await appendText(editor, `Sending GET request to ${url}${rejectUnauthorized ? '' : ' (allowing unauthorized)'}...`);
	try {
		const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
			const httpx = url.startsWith('https:') ? https : http;
			const req = httpx.get(url, { rejectUnauthorized }, resolve);
			req.on('error', reject);
		});
		const cert = res.socket instanceof tls.TLSSocket ? (res.socket as tls.TLSSocket).getPeerCertificate(true) : undefined;
		await appendText(editor, 'Received response code: ' + res.statusCode);
		if (cert) {
			await appendText(editor, `Certificate chain:`);
			let current = cert;
			const seen = new Set<string>();
			while (current && !seen.has(current.fingerprint)) {
				await appendText(editor, `- Subject: ${current.subject.CN}${current.subject.O ? ` (${current.subject.O})` : ''}`);
				if (current.subjectaltname) {
					await appendText(editor, `  Subject alt: ${current.subjectaltname}`);
				}
				await appendText(editor, `  Validity: ${current.valid_from} - ${current.valid_to}`);
				await appendText(editor, `  Fingerprint: ${current.fingerprint}`);
				if (!current.issuerCertificate) {
					await appendText(editor, `  Issuer certificate not found: ${current.issuer.CN}${current.issuer.O ? ` (${current.issuer.O})` : ''}`);
				} else if (current.issuerCertificate.fingerprint === current.fingerprint) {
					await appendText(editor, `  Self-signed`);
				}
				seen.add(current.fingerprint);
				current = current.issuerCertificate;
			}
		}
	} catch (err) {
		await appendText(editor, 'Received error: ' + (err as any)?.message);
	}
}

async function logSettings(editor: vscode.TextEditor) {
	await appendText(editor, 'Settings:');
	const settingsIds = ['http.proxy', 'http.proxyAuthorization', 'http.proxyStrictSSL', 'http.proxySupport', 'http.systemCertificates'];
	const conf = vscode.workspace.getConfiguration();
	for (const id of settingsIds) {
		await appendText(editor, `- ${id}: ${conf.get<string>(id)}`);
		const obj = conf.inspect<string>(id);
		for (const key in obj) {
			const value = (obj as any)[key];
			if (key !== 'key' && key !== 'defaultValue' && value !== undefined) {
				await appendText(editor, `  - ${key}: ${value}`);
			}
		}
	}
	await appendText(editor, '');
}

async function logEnvVariables(editor: vscode.TextEditor) {
	await appendText(editor, 'Environment variables:');
	const envVars = ['http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy'];
	for (const env in process.env) {
		if (envVars.includes(env.toLowerCase())) {
			await appendText(editor, `${env}=${process.env[env]}`);
		}
	}
	await appendText(editor, '');
}

async function appendText(editor: vscode.TextEditor, string: string) {
	await editor.edit(builder => {
		builder.insert(editor.document.lineAt(editor.document.lineCount - 1).range.end, string + '\n');
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

// From https://github.com/microsoft/vscode-proxy-agent/blob/4410a426f444c1203142c0b72dd09f63650ba1a4/src/index.ts#L401:

async function readCaCertificates() {
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
	return {
		certs: Array.from(certs),
		append: true
	};
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
	return {
		certs: Array.from(certs),
		append: true
	};
}

const linuxCaCertificatePaths = [
	'/etc/ssl/certs/ca-certificates.crt',
	'/etc/ssl/certs/ca-bundle.crt',
];

async function readLinuxCaCertificates() {
	for (const certPath of linuxCaCertificatePaths) {
		try {
			const content = await fs.promises.readFile(certPath, { encoding: 'utf8' });
			const certs = new Set(content.split(/(?=-----BEGIN CERTIFICATE-----)/g)
				.filter(pem => !!pem.length));
			return {
				certs: Array.from(certs),
				append: false
			};
		} catch (err: any) {
			if (err?.code !== 'ENOENT') {
				throw err;
			}
		}
	}
	return undefined;
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
