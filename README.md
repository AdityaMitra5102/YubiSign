# YubiSign

Yubikey 5.8 powered PDF signing with ARKG

YubiSign is a Python application with web interface that leverages Yubikey 5.8's PreviewSign Extension with Asynchronous Remote Key Generation (ARKG) to sign PDF documents. While the demonstration is only for PDF signing, the project lays the framework for generating X509 certificates for standard digital signing workflows.

# Problem solved:

Document signature, especially PDF files have been one of the most widely used operations with Public Key cryptography. It has been used time and again to prove the validity and legitimacy of documents. However, signing the same with hardware-backed cryptography in a reliable way has been a challenge so far. Some solutions required extensive setups involving PIV cards, HSMs etc., to usage of applications like GnuPG. 

This project aims at streamlining the workflow for signing documents. It leverages the WebAuthn PreviewSign extension with ARKG to sign PDF files with a Yubikey. It leverages standard PKCS#7 operations, making the signatures compliant with PDF/A technology, verifiable with PDF readers like Adobe Acrobat readers.

The advantages of using YubiSign:
- Secrets are hardware backed: Private keys are securely stored in the Yubikeys and cannot be extracted or easily compromised. The signing happens in the Yubikey.
- Easy of use: Extensive setups with PIV, GnuPG, etc., is not required for reliable PDF signing.
- Unlinkability: Multiple self-signed certificates and keypairs for PDF signing can be made from a single FIDO credential with ARKG, where they cannot be cryptographically linked.

## Secondary problem statement

While this problem is not related to the chosen problem statement, it was instrumental in fast development of the solution. I am developing on a Windows system. Windows FIDO2 client implemented under `webauthn.dll` does not support the `PreviewSign` extension and drops the calls. The only way to use it was to run the application with elevated privileges. Now running a whole python application which potentially interacts with artifacts from the internet (PDF Files) and uses the `pickle` library with elevated privileges is definetely a terrible idea. (I know I should have used better serialization than `pickle` but shortage of time in this hackathon forced me to use it.) It could make the application an easy target for RCE vulnerabilities. Hence, I developed an IPC based daemon which ran using `system` privileges, thus not fully-elevated but allows direct CTAP access over HID channels. 

The same is mentioned in the codebase at [IPC Calls](https://github.com/AdityaMitra5102/YubiSign/blob/c081affdbf1493b29c7c2c071eb753deed399ce8/flaskapp.py#L21). Installing the IPC Daemon can be done by installing the `python-fido2` library from my fork and branch at [Repo](https://github.com/AdityaMitra5102/python-fido2/tree/namedpipe#installation). Keeping the daemon active ensures the application can run directly without having to run with elevated privileges.

# Yubikey 5.8 specific feature

