# Detect Trusted Platform Modules Vulnerable to CVE-2017-15361 
This repository provides content for aiding DoD administrators in detecting systems that have an enabled Trusted Platform Module (TPM) that is vulnerable to CVE-2017-15361 and is a companion to Information Assurance Advisory [RSA Key Generation Vulnerability Affecting Trusted Platform Modules](https://www.iad.gov/iad/library/ia-advisories-alerts/rsa-key-generation-vulnerability-affecting-trusted-platform.cfm). The files in this repository can be downloaded as a zip file [here](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM/archive/master.zip).

The main files of interest in the repository include:
* [windows/Detect-CVE-2017-15361-TPM.audit](windows/Detect-CVE-2017-15361-TPM.audit) - a custom Nessus audit file useful for DoD administrators who want to scan Windows systems on their network with Nessus (acquire via the [ACAS](https://www.disa.mil/cybersecurity/network-defense/acas) program). TPM 1.2 and TPM 2.0 devices are supported.
* [windows/Detect-CVE-2017-15361-TPM.ps1](windows/Detect-CVE-2017-15361-TPM.ps1) - a PowerShell script useful for DoD administrators who want to locally test a single, standalone system. TPM 1.2 and TPM 2.0 devices are supported.
* [linux/Detect-CVE-2017-15361-TPM.audit](linux/Detect-CVE-2017-15361-TPM.audit) - a custom Nessus audit file useful for DoD administrators who want to scan Linux systems on their network with Nessus (acquire via the [ACAS](https://www.disa.mil/cybersecurity/network-defense/acas) program). Only TPM 1.2 devices are supported.
* [linux/Detect-CVE-2017-15361-TPM.sh](linux/Detect-CVE-2017-15361-TPM.sh) - a bash script useful for DoD users who want to locally test a single, standalone Linux system. Only TPM 1.2 devices are supported.



Support files in the repository include:
* [GenerateWindowsNessusAuditFile.ps1](windows/GenerateWindowsNessusAuditFile.ps1) - a PowerShell script that generates the Detect-CVE-2017-15361-TPM.audit file for Windows based on code in the Detect-CVE-2017-15361-TPM.ps1 file.

Infineon TPM firmware versions affected:
*   4.0 -   4.33
*   4.4 -   4.42
*   5.0 -   5.61
*   6.0 -   6.42
*   7.0 -   7.61
* 133.0 - 133.32
* 149.0 - 149.32

## Links
Original research identifying the issue:
* https://crocs.fi.muni.cz/public/papers/rsa_ccs17

More information about the vulnerability:
* https://www.kb.cert.org/vuls/id/307015
* https://www.infineon.com/cms/en/product/promopages/rsa-update/
* https://www.infineon.com/cms/en/product/promopages/rsa-update/rsa-background
* https://www.infineon.com/cms/en/product/promopages/tpm-update/

More information on operating system patches and TPM firmware updates:
* https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV170012
* https://us.answers.acer.com/app/answers/detail/a_id/51137
* http://www.fujitsu.com/global/support/products/software/security/products-f/ifsa-201701e.html
* https://support.hp.com/us-en/document/c05792935
* https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03789en_us 
* https://support.lenovo.com/us/en/product_security/LEN-15552
* https://support.toshiba.com/sscontent?contentId=4015874
* https://sites.google.com/a/chromium.org/dev/chromium-os/tpm_firmware_update

More information about other devices that are affected:
* https://www.yubico.com/support/security-advisories/ysa-2017-01/
* https://safenet.gemalto.com/technical-support/security-updates and https://gemalto.service-now.com/csm?id=kb_article&sys_id=19a55bdf4fb907c0873b69d18110c768

Tools for checking if your RSA key is affected:
* https://github.com/crocs-muni/roca
* https://keychest.net/roca
* https://keytester.cryptosense.com/
* https://www.tenable.com/plugins/index.php?view=single&id=103864

## License
See [LICENSE](./LICENSE.md).

## Disclaimer
See [DISCLAIMER](./DISCLAIMER.md).
