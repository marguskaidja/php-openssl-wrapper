<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Parameter;

use margusk\OpenSSL\Wrapper\Call;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Parameter;
use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey as Key;
use margusk\OpenSSL\Wrapper\Parameter\Certificate as Cert;
use margusk\OpenSSL\Wrapper\Proxy;
use margusk\OpenSSL\Wrapper\Result\Array_ as ArrayResult;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as KeyResult;
use margusk\OpenSSL\Wrapper\Result\Bool_ as BoolResult;
use margusk\OpenSSL\Wrapper\Result\Certificate as CertResult;
use margusk\OpenSSL\Wrapper\Result\Int_ as IntResult;
use margusk\OpenSSL\Wrapper\Result\String_ as StringResult;
use OpenSSLCertificate;

class Certificate extends Parameter
{
    public function __construct(
        Proxy $proxy,
        OpenSSLCertificate $internal
    ) {
        parent::__construct($proxy, $internal);
    }

    public function internal(): OpenSSLCertificate
    {
        return $this->internal;
    }

    /**
     * Opens (decrypts) data using the private key associated with the key identifier private_key and
     * the envelope key encrypted_key, and fills output with the decrypted data.
     * The envelope key is generated when the data are sealed and can only be used by one specific private
     * key.
     *
     * @see  Proxy::seal()
     * @link https://www.php.net/manual/en/function.openssl-open.php
     */
    public function open(
        string $data,
        string $encryptedKey,
        string $cipherAlgo,
        ?string $iv = null
    ): StringResult {
        return $this->proxy->open($data, $encryptedKey, $this, $cipherAlgo, $iv);
    }

    /**
     * Stores certificate into a file named by output_filename in a PKCS#12 file format.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export-to-file.php
     */
    public function pkcs12ExportToFile(
        Cert|OpenSSLCertificate|string $certificate,
        string $outputFilename,
        string $passphrase,
        array $options = []
    ): BoolResult {
        return $this->proxy->pkcs12ExportToFile($this, $outputFilename, $privateKey, $passphrase, $options);
    }

    /**
     * Stores certificate into a string named by output in a PKCS#12 file format.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export.php
     */
    public function pkcs12Export(
        Cert|OpenSSLCertificate|string $certificate,
        string $passphrase,
        array $options = []
    ): StringResult {
        return $this->proxy->pkcs12Export($this, $privateKey, $passphrase, $options);
    }

    /**
     * Saves an ascii-armoured (PEM encoded) rendition of key into the file named by outputFilename.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export-to-file.php
     */
    public function pkeyExportToFile(
        string $outputFilename,
        ?string $passphrase = null,
        ?array $options = null
    ): BoolResult {
        return $this->proxy->pkeyExportToFile($this, $outputFilename, $passphrase, $options);
    }

    /**
     * Returns exported key as a PEM encoded string
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export.php
     */
    public function pkeyExport(?string $passphrase = null, ?array $options = null): StringResult
    {
        return $this->proxy->pkeyExport($this, $passphrase, $options);
    }

    /**
     * Parses private_key and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     */
    public function pkeyGetPrivate(?string $passphrase = null): KeyResult
    {
        return $this->proxy->pkeyGetPrivate($this, $passphrase);
    }

    /**
     * Extracts the public key from publicKey and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-public.php
     */
    public function pkeyGetPublic(): KeyResult
    {
        return $this->proxy->pkeyGetPublic($this);
    }

    /**
     * Decrypts data that was previously encrypted via openssl_public_encrypt()
     * and returns the result
     *
     * @link https://www.php.net/manual/en/function.openssl-private-decrypt.php
     */
    public function privateDecrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): StringResult
    {
        return $this->proxy->privateDecrypt($data, $this, $padding);
    }

    /**
     * Encrypts data with private privateKey and returns the result.
     * Encrypted data can be decrypted via openssl_public_decrypt().
     *
     * @link https://www.php.net/manual/en/function.openssl-private-encrypt.php
     */
    public function privateEncrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): StringResult
    {
        return $this->proxy->privateEncrypt($data, $this, $padding);
    }

    /**
     * Decrypts data that was previous encrypted via openssl_private_encrypt()
     * and returns the result.
     *
     * @link https://www.php.net/manual/en/function.openssl-public-decrypt.php
     */
    public function publicDecrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): StringResult
    {
        return $this->proxy->publicDecrypt($data, $this, $padding);
    }

    /**
     * Encrypts data with public publicKey and returns the result.
     *
     * @link https://www.php.net/manual/en/function.openssl-public-encrypt.php
     */
    public function publicEncrypt(
        string $data,
        int $padding = OPENSSL_PKCS1_PADDING
    ): StringResult {
        return $this->proxy->publicEncrypt($data, $this, $padding);
    }

    /**
     * Generate signature
     *
     * @link https://www.php.net/manual/en/function.openssl-sign.php
     */
    public function sign(string $data, string|int $algorithm = OPENSSL_ALGO_SHA1): StringResult
    {
        return $this->proxy->sign($data, $this, $algorithm);
    }

    /**
     * Verifies that the signature is correct for the specified data using the
     * public key associated with publicKey.
     *
     * @link https://www.php.net/manual/en/function.openssl-verify.php
     */
    public function verify(
        string $data,
        string $signature,
        string|int $algorithm = OPENSSL_ALGO_SHA1
    ): BoolResult {
        return $this->proxy->verify($data, $signature, $this, $algorithm);
    }

    /**
     * Checks whether the given privateKey is the private key that corresponds to certificate.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-check-private-key.php
     */
    public function x509CheckPrivateKey(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey
    ): BoolResult {
        return $this->proxy->x509CheckPrivateKey($this, $privateKey);
    }

    /**
     * Examines a certificate to see if it can be used for the specified purpose.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-checkpurpose.php
     */
    public function x509Checkpurpose(
        int $purpose,
        array $caInfo = [],
        ?string $untrustedCertificatesFile = null
    ): BoolResult {
        return $this->proxy->x509Checkpurpose($this, $purpose, $caInfo, $untrustedCertificatesFile);
    }

    /**
     * Stores certificate into a file named by output_filename in a PEM encoded format.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export-to-file.php
     */
    public function x509ExportToFile(string $outputFilename, bool $noText = true): BoolResult
    {
        return $this->proxy->x509ExportToFile($this, $outputFilename, $noText);
    }

    /**
     * Stores certificate into a string named by output in a PEM encoded format.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export.php
     */
    public function x509Export(bool $noText = true): StringResult
    {
        return $this->proxy->x509Export($this, $noText);
    }

    /**
     * Returns the digest of certificate as a string.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-fingerprint.php
     */
    public function x509Fingerprint(
        string $digestAlgo = "sha1",
        bool $binary = false
    ): StringResult {
        return $this->proxy->x509Fingerprint($this, $digestAlgo, $binary);
    }

    /**
     * Returns information about the supplied certificate, including fields such
     * as subject name, issuer name, purposes, valid from and valid to dates etc.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-parse.php
     */
    public function x509Parse(bool $shortNames = true): ArrayResult
    {
        return $this->proxy->x509Parse($this, $shortNames);
    }

    /**
     * Verifies that the certificate certificate was signed by the private key corresponding to
     * public key public_key.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-verify.php
     */
    public function x509Verify(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey
    ): IntResult {
        return $this->proxy->x509Verify($this, $publicKey);
    }
}
