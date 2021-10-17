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

use margusk\OpenSSL\Wrapper\Call;
use margusk\OpenSSL\Wrapper\Parameter;
use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey as Key;
use margusk\OpenSSL\Wrapper\Parameter\Certificate as Cert;
use margusk\OpenSSL\Wrapper\Proxy;
use margusk\OpenSSL\Wrapper\Result\Array_ as ArrayResult;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as KeyResult;
use margusk\OpenSSL\Wrapper\Result\Bool_ as BoolResult;
use margusk\OpenSSL\Wrapper\Result\Certificate as CertResult;
use margusk\OpenSSL\Wrapper\Result\String_ as StringResult;
use OpenSSLCertificateSigningRequest;
use OpenSSLCertificate;
use OpenSSLAsymmetricKey;

class CSR extends Parameter
{
    public function __construct(
        Proxy $proxy,
        OpenSSLCertificateSigningRequest $internal
    ) {
        parent::__construct($proxy, $internal);
    }

    public function internal(): OpenSSLCertificateSigningRequest
    {
        return $this->internal;
    }

    /**
     * Takes the Certificate Signing Request represented by csr and saves it in
     * PEM format into the file named by output_filename.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-export-to-file.php
     */
    public function csrExportToFile(string $outputFilename, bool $noText = true): BoolResult
    {
        return $this->proxy->csrExportToFile($this, $outputFilename, $noText);
    }

    /**
     * Takes the Certificate Signing Request represented by csr and stores it in
     * PEM format in output, which is passed by reference.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-export.php
     */
    public function csrExport(bool $noText = true): StringResult
    {
        return $this->proxy->csrExport($this, $noText);
    }

    /**
     * Extracts the public key from csr and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-get-public-key.php
     */
    public function csrGetPublicKey(bool $shortNames = true): KeyResult
    {
        return $this->proxy->csrGetPublicKey($this, $shortNames);
    }

    /**
     * Returns subject distinguished name information encoded in the csr including
     * fields commonName (CN), organizationName (O), countryName (C) etc.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-get-subject.php
     */
    public function csrGetSubject(bool $shortNames = true): ArrayResult
    {
        return $this->proxy->csrGetSubject($shortNames);
    }

    /**
     * Generates an x509 certificate from the given CSR.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-sign.php
     */
    public function csrSign(
        Cert|OpenSSLCertificate|string|null $caCertificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        int $days,
        ?array $options = null,
        int $serial = 0
    ): CertResult {
        return $this->proxy->csrSign($this, $caCertificate, $privateKey, $days, $options, $serial);
    }
}
