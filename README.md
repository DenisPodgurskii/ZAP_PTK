# ZAP PTK Add-on

This ZAP add-on provides integration with [OWASP Penetration Testing Kit (PTK)](https://pentestkit.co.uk/).

[OWASP PTK](https://pentestkit.co.uk/) is a browser-based application security tool that turns your browser into a comprehensive security testing platform. It provides:

- **DAST** (Dynamic Application Security Testing) - Identify SQL injection, command injection, reflected/stored XSS
- **IAST** (Interactive Application Security Testing) - Track taint flows and code execution at runtime
- **SAST** (Static Code Analysis) - Flag unsafe patterns in scripts
- **SCA** (Software Composition Analysis) - Find outdated or vulnerable packages
- **Request Builder** - Tamper requests and run DAST attacks
- **JWT Inspector** - Analyze, craft, and tamper with JSON Web Tokens
- **Dashboard** - Visibility into tech stacks, WAFs, security headers, and more
- **Cookie Editor** - Manage cookies and create protection rules
- **Automation** - Integrate with browser automation systems
- **Recording** - Macro and traffic recording capabilities

This ZAP add-on enables seamless integration between ZAP and OWASP PTK, allowing security testers to leverage both tools together for comprehensive application security testing.

For more information about OWASP PTK, visit [https://pentestkit.co.uk/](https://pentestkit.co.uk/)

## Development Notes

To deploy to `../zaprozy` : `./gradlew copyZapAddOn`

To deploy to `../zaproxy` and use a local add-on : `./gradlew copyZapAddOn --include-build=../zap-extensions`

To apply code formatting: `./gradlew spotlessApply`

