/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';

export function activate(context: vscode.ExtensionContext) {

	let expectedUrl: string;
	let actualResponse: string;

	const agent = requireFromApp('vscode-proxy-agent/out/agent');
	const origCallback = agent.PacProxyAgent.prototype.callback;
	agent.PacProxyAgent.prototype.callback = function (...args: any[]) {
		if (!this.resolverPatched) {
			this.resolverPatched = true;
			const origResolver = this.resolver;
			this.resolver = async (...args: any[]) => {
				const url = args[2];
				const res = await origResolver.apply(this, args);
				if (url === expectedUrl || url === expectedUrl + '/') {
					actualResponse = res;
				}
				return res;
			};
		}
		return origCallback.apply(this, args);
	};

	context.subscriptions.push(vscode.commands.registerCommand('network-proxy-test.test-connection', async () => {
		const url = await vscode.window.showInputBox({
			prompt: 'Enter URL to probe',
			value: 'https://example.com',
		});
		if (!url) {
			return;
		}

		const document = await vscode.workspace.openTextDocument({ language: 'text' });
		const editor = await vscode.window.showTextDocument(document);
		await appendText(editor, `Note: Make sure to replace all sensitive information with dummy values before sharing this output.\n`);
		expectedUrl = url;
		await probeUrl(editor, url);
		await logSettings(editor);
		await logEnvVariables(editor);
		await appendText(editor, `vscode-proxy-agent: ${actualResponse}`);
	}));
}

async function probeUrl(editor: vscode.TextEditor, url: string) {
	await appendText(editor, `Sending GET request to ${url}...`);
	try {
		const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
			const req = https.get(url, resolve);
			req.on('error', reject);
		});
		await appendText(editor, 'Received response code: ' + res.statusCode);
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
}

async function logEnvVariables(editor: vscode.TextEditor) {
	await appendText(editor, 'Environment variables:');
	const envVars = ['http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy'];
	for (const env in process.env) {
		if (envVars.includes(env.toLowerCase())) {
			await appendText(editor, `${env}=${process.env[env]}`);
		}
	}
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
