# Network Proxy Test

VS Code extension to test network settings.

## Usage

In VS Code: `F1` > `Network Proxy Test: Test Connection`, enter the URL to test or use default. This will open a new editor and log the results.

If that shows a certificate error, try `F1` > `Network Proxy Test: Test Connection (Allow Unauthorized)` to get information on the certificate chain in the server's response.

Use `F1` > `Network Proxy Test: Show OS Certificates` to check if the required root certificate is loaded from the OS.

## License

[MIT](LICENSE)
