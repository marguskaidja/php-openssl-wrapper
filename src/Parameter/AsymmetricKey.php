<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Parameter;

use margusk\OpenSSL\Wrapper\Parameter;
use margusk\OpenSSL\Wrapper\Proxy;
use margusk\OpenSSL\Wrapper\Result\Array_ as ArrayResult;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as KeyResult;
use margusk\OpenSSL\Wrapper\Result\Bool_ as BoolResult;
use margusk\OpenSSL\Wrapper\Result\CSRNew as CSRNewResult;
use margusk\OpenSSL\Wrapper\Result\String_ as StringResult;
use OpenSSLAsymmetricKey;

/**
 * @property-read OpenSSLAsymmetricKey $internal
 */
class AsymmetricKey extends Parameter
{
    public function __construct(
        Proxy $proxy,
        OpenSSLAsymmetricKey $internal
    ) {
        parent::__construct($proxy, $internal);
    }

    /**
     * Generates a new CSR (Certificate Signing Request) based on the information provided by distinguished_names.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-new.php
     */
    public function csrNew(
        array $distinguishedNames,
        ?array $options = null,
        ?array $extraAttributes = null
    ): CSRNewResult {
        return $this->proxy->csrNew($distinguishedNames, $this, $options, $extraAttributes);
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
     * Returns an array with the key details
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function pkeyGetDetails(): ArrayResult
    {
        return $this->proxy->pkeyGetDetails($this);
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
}
