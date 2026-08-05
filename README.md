# YubiSign

Yubikey 5.8 powered PDF signing with ARKG

# Problem solved:

Document signature, especially PDF files have been one of the most widely used operations with Public Key cryptography. It has been used time and again to prove the validity and legitimacy of documents. However, signing the same with hardware-backed cryptography in a reliable way has been a challenge so far. Some solutions required extensive setups involving PIV cards, HSMs etc., to usage of applications like GnuPG. 

This project aims at streamlining the workflow for signing documents. It leverages the WebAuthn PreviewSign extension with ARKG to sign PDF files with a Yubikey. It leverages standard PKCS#7 operations, making the signatures compliant with PDF/A technology, verifiable with PDF readers like Adobe Acrobat readers.

The advantages of using YubiSign:
- Secrets are hardware backed: Private keys are securely stored in the Yubikeys and cannot be extracted or easily compromised. The signing happens in the Yubikey.
- Easy of use: Extensive setups with PIV, GnuPG, etc., is not required for reliable PDF signing.
- Unlinkability: Multiple self-signed certificates and keypairs for PDF signing can be made from a single FIDO credential with ARKG, where they cannot be cryptographically linked.

