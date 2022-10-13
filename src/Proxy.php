<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper;

use margusk\GetSet\Attributes\Get;
use margusk\GetSet\GetSetTrait;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey as Key;
use margusk\OpenSSL\Wrapper\Parameter\Certificate as Cert;
use margusk\OpenSSL\Wrapper\Parameter\CSR;
use margusk\OpenSSL\Wrapper\Proxy\Options;
use margusk\OpenSSL\Wrapper\Result\Array_ as ArrayResult;
use margusk\OpenSSL\Wrapper\Result\AsymmetricKey as KeyResult;
use margusk\OpenSSL\Wrapper\Result\Bool_ as BoolResult;
use margusk\OpenSSL\Wrapper\Result\Certificate as CertResult;
use margusk\OpenSSL\Wrapper\Result\Encrypt as EncryptResult;
use margusk\OpenSSL\Wrapper\Result\Int_ as IntResult;
use margusk\OpenSSL\Wrapper\Result\RandomPseudoBytes as RandomPseudoBytesResult;
use margusk\OpenSSL\Wrapper\Result\Seal as SealResult;
use margusk\OpenSSL\Wrapper\Result\String_ as StringResult;
use margusk\OpenSSL\Wrapper\Result\CSRNew as CSRNewResult;
use margusk\OpenSSL\Wrapper\Call\WithNoFailuresExpected as CallWithNoFailuresExpected;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * @method Options options()
 */
#[Get]
class Proxy
{
    use GetSetTrait;

    public function __construct(
        protected ?Options $options = null
    ) {
        if (null === $this->options) {
            $this->options = new Options();
        }
    }

    /**
     * Gets the cipher initialization vector (iv) length.
     *
     * @link   https://www.php.net/manual/en/function.openssl-cipher-iv-length
     *
     * @param  string  $cipherAlgo  The cipher method, see openssl_get_cipher_methods for a list of potential values.
     *
     * @return Int
     * @throws OpenSSLCallFailedException
     */
    public function cipherIvLength(string $cipherAlgo): IntResult
    {
        return (new Call($this, 'cipher_iv_length'))
            ->withParameters([$cipherAlgo])
            ->getIntResult();
    }

    /**
     * Decrypt a CMS message
     *
     * @link https://www.php.net/manual/en/function.openssl-cms-decrypt.php
     */
    public function cmsDecrypt(
        string $inputFilename,
        string $outputFilename,
        Cert|OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string|null $privateKey = null,
        int $encoding = OPENSSL_ENCODING_SMIME
    ): BoolResult {
        return (new Call($this, 'cms_decrypt'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * This function encrypts content to one or more recipients, based on the certificates that are passed to it.
     *
     * @link https://www.php.net/manual/en/function.openssl-cms-encrypt.php
     */
    public function cmsEncrypt(
        string $inputFilename,
        string $outputFilename,
        Cert|OpenSSLCertificate|array|string $certificate,
        ?array $headers,
        int $flags = 0,
        int $encoding = OPENSSL_ENCODING_SMIME,
        int $cipherAlgo = OPENSSL_CIPHER_RC2_40
    ): BoolResult {
        return (new Call($this, 'cms_encrypt'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Export the CMS file to an array of PEM certificates
     *
     * @link https://www.php.net/manual/en/function.openssl-cms-read.php
     */
    public function cmsRead(string $inputFilename): ArrayResult
    {
        return (new Call($this, 'cms_read'))
            ->with([
                'parameters' => [
                    $inputFilename,
                    null
                ],
                'returnNthParameter' => 1
            ])
            ->getArrayResult();
    }

    /**
     * This function signs a file with an X.509 certificate and key.
     *
     * @link https://www.php.net/manual/en/function.openssl-cms-sign.php
     */
    public function cmsSign(
        string $inputFilename,
        string $outputFilename,
        Cert|OpenSSLCertificate|string $certificate,
        Cert|Key|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        ?array $headers,
        int $flags = 0,
        int $encoding = OPENSSL_ENCODING_SMIME,
        ?string $untrustedCertificatesFilename = null
    ): BoolResult {
        return (new Call($this, 'cms_sign'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * This function verifies a CMS signature, either attached or detached, with the specified encoding.
     *
     * @link https://www.php.net/manual/en/function.openssl-cms-verify.php
     */
    public function cmsVerify(
        string $input_filename,
        int $flags = 0,
        ?string $certificates = null,
        array $caInfo = [],
        ?string $untrustedCertificatesFilename = null,
        ?string $content = null,
        ?string $pk7 = null,
        ?string $sigfile = null,
        int $encoding = OPENSSL_ENCODING_SMIME
    ): BoolResult {
        return (new CallWithNoFailuresExpected($this, 'cms_verify'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Takes the Certificate Signing Request represented by csr and saves it in
     * PEM format into the file named by output_filename.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-export-to-file.php
     */
    public function csrExportToFile(
        CSR|OpenSSLCertificateSigningRequest|string $csr,
        string $outputFilename,
        bool $noText = true
    ): BoolResult {
        return (new Call($this, 'csr_export_to_file'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Takes the Certificate Signing Request represented by csr and stores it in
     * PEM format in output, which is passed by reference.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-export.php
     */
    public function csrExport(
        CSR|OpenSSLCertificateSigningRequest|string $csr,
        bool $noText = true
    ): StringResult {
        return (new Call($this, 'csr_export'))
            ->with([
                'parameters' => [
                    $csr,
                    '',
                    $noText
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Extracts the public key from csr and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-get-public-key.php
     */
    public function csrGetPublicKey(
        CSR|OpenSSLCertificateSigningRequest|string $csr,
        bool $shortNames = true
    ): KeyResult {
        return (new Call($this, 'csr_get_public_key'))
            ->withParameters(func_get_args())
            ->getKeyResult();
    }

    /**
     * Returns subject distinguished name information encoded in the csr including
     * fields commonName (CN), organizationName (O), countryName (C) etc.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-get-subject.php
     */
    public function csrGetSubject(
        CSR|OpenSSLCertificateSigningRequest|string $csr,
        bool $shortNames = true
    ): ArrayResult {
        return (new Call($this, 'csr_get_subject'))
            ->withParameters(func_get_args())
            ->getArrayResult();
    }

    /**
     * Generates a new CSR (Certificate Signing Request) based on the information provided by distinguished_names.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-new.php
     */
    public function csrNew(
        array $distinguishedNames,
        Key|OpenSSLAsymmetricKey|null $privateKey,
        ?array $options = null,
        ?array $extraAttributes = null
    ): CSRNewResult {
        return (new Call($this, 'csr_new'))
            ->withParameters(func_get_args())
            ->getCSRNewResult();
    }

    /**
     * Generates an x509 certificate from the given CSR.
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-sign.php
     */
    public function csrSign(
        CSR|OpenSSLCertificateSigningRequest|string $csr,
        Cert|OpenSSLCertificate|string|null $caCertificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        int $days,
        ?array $options = null,
        int $serial = 0
    ): CertResult {
        return (new Call($this, 'csr_sign'))
            ->withParameters(func_get_args())
            ->getCertResult();
    }

    /**
     * Takes a raw or base64 encoded string and decrypts it using a given method and key.
     *
     * @link https://www.php.net/manual/en/function.openssl-decrypt.php
     */
    public function decrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = "",
        string $tag = "",
        string $aad = ""
    ): StringResult {
        return (new Call($this, 'decrypt'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Computes shared secret for public value of remote DH public key and local DH key
     *
     * @link https://www.php.net/manual/en/function.openssl-dh-compute-key.php
     */
    public function dhComputeKey(
        string $publicKey,
        Key|OpenSSLAsymmetricKey $privateKey
    ): StringResult {
        return (new Call($this, 'dh_compute_key'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Computes a digest hash value for the given data using a given method, and returns a raw or binhex encoded string.
     *
     * @link https://www.php.net/manual/en/function.openssl-digest.php
     */
    public function digest(
        string $data,
        string $digestAlgo,
        bool $binary = false
    ): StringResult {
        return (new Call($this, 'digest'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Encrypts given data with given method and key, returns a raw or base64 encoded string
     *
     * @link https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    public function encrypt(
        string $data,
        string $cipherAlgo,
        string $passphrase,
        int $options = 0,
        string $iv = "",
        string $aad = "",
        int $tagLength = 16
    ): EncryptResult {
        return (new Call($this, 'encrypt'))
            ->withParameters([
                $data,
                $cipherAlgo,
                $passphrase,
                $options,
                $iv,
                '',
                $aad,
                $tagLength
            ])
            ->getEncryptResult();
    }

    /**
     * Returns an array with information about the available certificate locations
     * that will be searched for SSL certificates.
     *
     * @link https://www.php.net/manual/en/function.openssl-get-cert-locations.php
     */
    public function getCertLocations(): ArrayResult
    {
        return (new CallWithNoFailuresExpected($this, 'get_cert_locations'))
            ->getArrayResult();
    }

    /**
     * Gets available cipher methods
     *
     * @link   https://www.php.net/manual/en/function.openssl-get-cipher-methods
     */
    public function getCipherMethods(bool $aliases = false): ArrayResult
    {
        return (new CallWithNoFailuresExpected($this, 'get_cipher_methods'))
            ->withParameters(func_get_args())
            ->getArrayResult();
    }

    /**
     * Returns an array with information about the available certificate locations
     * that will be searched for SSL certificates.
     *
     * @link https://www.php.net/manual/en/function.openssl-get-cert-locations.php
     */
    public function getCurveNames(): ArrayResult
    {
        return (new Call($this, 'get_curve_names'))
            ->getArrayResult();
    }

    /**
     * Gets a list of available digest methods.
     *
     * @link https://www.php.net/manual/en/function.openssl-get-md-methods.php
     */
    public function getMdMethods(bool $aliases = false): ArrayResult
    {
        return (new CallWithNoFailuresExpected($this, 'get_md_methods'))
            ->withParameters(func_get_args())
            ->getArrayResult();
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
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        string $cipherAlgo,
        ?string $iv = null
    ): StringResult {
        return (new Call($this, 'open'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $encryptedKey,
                    $privateKey,
                    $cipherAlgo,
                    $iv
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Computes PBKDF2 (Password-Based Key Derivation Function 2), a key derivation function defined in PKCS5 v2.
     *
     * @link https://www.php.net/manual/en/function.openssl-pbkdf2.php
     */
    public function pbkdf2(
        string $password,
        string $salt,
        int $keyLength,
        int $iterations,
        string $digestAlgo = "sha1"
    ): StringResult {
        return (new Call($this, 'pbkdf2'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Stores certificate into a file named by output_filename in a PKCS#12 file format.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export-to-file.php
     */
    public function pkcs12ExportToFile(
        Cert|OpenSSLCertificate|string $certificate,
        string $outputFilename,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        string $passphrase,
        array $options = []
    ): BoolResult {
        return (new Call($this, 'pkcs12_export_to_file'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Stores certificate into a string named by output in a PKCS#12 file format.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export.php
     */
    public function pkcs12Export(
        Cert|OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        string $passphrase,
        array $options = []
    ): StringResult {
        return (new Call($this, 'pkcs12_export'))
            ->with([
                'parameters' => [
                    $certificate,
                    null,
                    $privateKey,
                    $passphrase,
                    $options
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Parses the PKCS#12 certificate store supplied by pkcs12 into a array named certificates.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-read.php
     */
    public function pkcs12Read(string $pkcs12, string $passphrase): ArrayResult
    {
        return (new Call($this, 'pkcs12_export'))
            ->with([
                'parameters' => [
                    $pkcs12,
                    null,
                    $passphrase
                ],
                'returnNthParameter' => 1
            ])
            ->getArrayResult();
    }

    /**
     * Decrypts the S/MIME encrypted message contained in the file specified by input_filename
     * using the certificate and its associated private key specified by certificate and private_key.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-decrypt.php
     */
    public function pkcs7Decrypt(
        string $inputFilename,
        string $outputFilename,
        OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string|null $privateKey = null
    ): BoolResult {
        return (new Call($this, 'pkcs7_decrypt'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Takes the contents of the file named input_filename and encrypts them using an RC2 40-bit cipher
     * so that they can only be read by the intended recipients specified by certificate.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php
     */
    public function pkcs7Encrypt(
        string $inputFilename,
        string $outputFilename,
        Cert|OpenSSLCertificate|array|string $certificate,
        ?array $headers,
        int $flags = 0,
        int $cipherAlgo = OPENSSL_CIPHER_RC2_40
    ): BoolResult {
        return (new Call($this, 'pkcs7_encrypt'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Export the PKCS7 file to an array of PEM certificates
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-read.php
     */
    public function pkcs7Read(string $data): ArrayResult
    {
        return (new Call($this, 'pkcs7_read'))
            ->with([
                'parameters' => [
                    $data,
                    null
                ],
                'returnNthParameter' => 1
            ])
            ->getArrayResult();
    }

    /**
     * Takes the contents of the file named inputFilename and signs them using the certificate
     * and its matching private key specified by certificate and privateKey parameters.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-sign.php
     */
    public function pkcs7Sign(
        string $inputFilename,
        string $outputFilename,
        Cert|OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        ?array $headers,
        int $flags = PKCS7_DETACHED,
        ?string $untrustedCertificatesFilename = null
    ): BoolResult {
        return (new Call($this, 'pkcs7_sign'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Reads the S/MIME message contained in the given file and examines the digital signature.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-verify.php
     */
    public function pkcs7Verify(
        string $inputFilename,
        int $flags,
        ?string $signersCertificatesFilename = null,
        array $caInfo = [],
        ?string $untrustedCertificatesFilename = null,
        ?string $content = null,
        ?string $outputFilename = null
    ): BoolResult {
        return (new Call($this, 'pkcs7_verify'))
            ->with([
                'parameters' => func_get_args(),
                'expectedFailures' => [false, -1]
            ])
            ->getBoolResult();
    }

    /**
     * Takes a set of a publicKey and privateKey and derives a shared secret, for either DH or EC keys.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-derive.php
     */
    public function pkeyDerive(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        int $keyLength = 0
    ): StringResult {
        return (new Call($this, 'pkey_derive'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Saves an ascii-armoured (PEM encoded) rendition of key into the file named by outputFilename.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export-to-file.php
     */
    public function pkeyExportToFile(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $key,
        string $outputFilename,
        ?string $passphrase = null,
        ?array $options = null
    ): BoolResult {
        return (new Call($this, 'pkey_export_to_file'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Returns exported key as a PEM encoded string
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export.php
     */
    public function pkeyExport(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $key,
        ?string $passphrase = null,
        ?array $options = null
    ): StringResult {
        return (new Call($this, 'pkey_export'))
            ->with([
                'parameters' => [
                    $key,
                    null,
                    $passphrase,
                    $options
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Returns an array with the key details
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     */
    public function pkeyGetDetails(Key|OpenSSLAsymmetricKey $key): ArrayResult
    {
        return (new Call($this, 'pkey_get_details'))
            ->withParameters(func_get_args())
            ->getArrayResult();
    }

    /**
     * Parses private_key and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     */
    public function pkeyGetPrivate(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        ?string $passphrase = null
    ): KeyResult {
        return (new Call($this, 'pkey_get_private'))
            ->withParameters(func_get_args())
            ->getKeyResult();
    }

    /**
     * Extracts the public key from publicKey and prepares it for use by other functions.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-public.php
     */
    public function pkeyGetPublic(
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey
    ): KeyResult {
        return (new Call($this, 'pkey_get_public'))
            ->withParameters(func_get_args())
            ->getKeyResult();
    }

    /**
     * Generates a new private key
     *
     * @link  https://www.php.net/manual/en/function.openssl-pkey-new.php
     */
    public function pkeyNew(?array $options = null): KeyResult
    {
        return (new Call($this, 'pkey_new'))
            ->withParameters(func_get_args())
            ->getKeyResult();
    }

    /**
     * Decrypts data that was previously encrypted via openssl_public_encrypt()
     * and returns the result
     *
     * @link https://www.php.net/manual/en/function.openssl-private-decrypt.php
     */
    public function privateDecrypt(
        string $data,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        int $padding = OPENSSL_PKCS1_PADDING
    ): StringResult {
        return (new Call($this, 'private_decrypt'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $privateKey,
                    $padding
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Encrypts data with private privateKey and returns the result.
     * Encrypted data can be decrypted via openssl_public_decrypt().
     *
     * @link https://www.php.net/manual/en/function.openssl-private-encrypt.php
     */
    public function privateEncrypt(
        string $data,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        int $padding = OPENSSL_PKCS1_PADDING
    ): StringResult {
        return (new Call($this, 'private_encrypt'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $privateKey,
                    $padding
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Decrypts data that was previous encrypted via openssl_private_encrypt()
     * and returns the result.
     *
     * @link https://www.php.net/manual/en/function.openssl-public-decrypt.php
     */
    public function publicDecrypt(
        string $data,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey,
        int $padding = OPENSSL_PKCS1_PADDING
    ): StringResult {
        return (new Call($this, 'public_decrypt'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $publicKey,
                    $padding
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Encrypts data with public publicKey and returns the result.
     *
     * @link https://www.php.net/manual/en/function.openssl-public-encrypt.php
     */
    public function publicEncrypt(
        string $data,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey,
        int $padding = OPENSSL_PKCS1_PADDING
    ): StringResult {
        return (new Call($this, 'public_encrypt'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $publicKey,
                    $padding
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Generates a string of pseudo-random bytes, with the number of bytes determined by the length parameter.
     * It also indicates if a cryptographically strong algorithm was used to produce the pseudo-random bytes,
     * and does this via the optional strong_result parameter. It's rare for this to be false, but some
     * systems may be broken or old.
     *
     * @link https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php
     */
    public function randomPseudoBytes(int $length): RandomPseudoBytesResult
    {
        return (new Call($this, 'random_pseudo_bytes'))
            ->withParameters([$length, null])
            ->getRandomPseudoBytesResult();
    }

    /**
     * Seals (encrypts) data by using the given cipher_algo with a randomly generated secret key.
     *
     * @link https://www.php.net/manual/en/function.openssl-seal.php
     */
    public function seal(
        string $data,
        array $publicKey,
        string $cipherAlgo,
    ): SealResult {
        return (new Call($this, 'seal'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    null,
                    $publicKey,
                    $cipherAlgo,
                    ''
                ],
                'returnNthParameter' => 1
            ])
            ->getSealResult();
    }

    /**
     * Generate signature
     *
     * @link https://www.php.net/manual/en/function.openssl-sign.php
     */
    public function sign(
        string $data,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey,
        string|int $algorithm = OPENSSL_ALGO_SHA1
    ): StringResult {
        return (new Call($this, 'sign'))
            ->with([
                'parameters' => [
                    $data,
                    null,
                    $privateKey,
                    $algorithm
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Exports challenge from encoded signed public key and challenge.
     *
     * @link https://www.php.net/manual/en/function.openssl-spki-export-challenge.php
     */
    public function spkiExportChallenge(string $spki): StringResult
    {
        return (new Call($this, 'spki_export_challenge'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Exports PEM formatted public key from encoded signed public key and challenge.
     *
     * @link https://www.php.net/manual/en/function.openssl-spki-export.php
     */
    public function spkiExport(string $spki): StringResult
    {
        return (new Call($this, 'spki_export'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Generates a signed public key and challenge using specified hashing algorithm.
     *
     * @link https://www.php.net/manual/en/function.openssl-spki-new.php
     */
    public function spkiNew(
        Key|OpenSSLAsymmetricKey $privateKey,
        string $challenge,
        int $digestAlgo = OPENSSL_ALGO_MD5
    ): StringResult {
        return (new Call($this, 'spki_new'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Validates the supplied signed public key and challenge
     *
     * @link https://www.php.net/manual/en/function.openssl-spki-verify.php
     */
    public function spkiVerify(string $spki): BoolResult
    {
        return (new Call($this, 'spki_verify'))
            ->withParameters(func_get_args())
            ->getBoolResult();
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
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey,
        string|int $algorithm = OPENSSL_ALGO_SHA1
    ): BoolResult {
        return (new Call($this, 'verify'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Checks whether the given privateKey is the private key that corresponds to certificate.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-check-private-key.php
     */
    public function x509CheckPrivateKey(
        Cert|OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $privateKey
    ): BoolResult {
        return (new CallWithNoFailuresExpected($this, 'x509_check_private_key'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Examines a certificate to see if it can be used for the specified purpose.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-checkpurpose.php
     */
    public function x509Checkpurpose(
        Cert|OpenSSLCertificate|string $certificate,
        int $purpose,
        array $caInfo = [],
        ?string $untrustedCertificatesFile = null
    ): BoolResult {
        return (new CallWithNoFailuresExpected($this, 'x509_checkpurpose'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Stores certificate into a file named by output_filename in a PEM encoded format.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export-to-file.php
     */
    public function x509ExportToFile(
        Cert|OpenSSLCertificate|string $certificate,
        string $outputFilename,
        bool $noText = true
    ): BoolResult {
        return (new Call($this, 'x509_export_to_file'))
            ->withParameters(func_get_args())
            ->getBoolResult();
    }

    /**
     * Stores certificate into a string named by output in a PEM encoded format.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export.php
     */
    public function x509Export(
        Cert|OpenSSLCertificate|string $certificate,
        bool $noText = true
    ): StringResult {
        return (new Call($this, 'x509_export'))
            ->with([
                'parameters' => [
                    $certificate,
                    null,
                    $noText
                ],
                'returnNthParameter' => 1
            ])
            ->getStringResult();
    }

    /**
     * Returns the digest of certificate as a string.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-fingerprint.php
     */
    public function x509Fingerprint(
        Cert|OpenSSLCertificate|string $certificate,
        string $digestAlgo = "sha1",
        bool $binary = false
    ): StringResult {
        return (new Call($this, 'x509_fingerprint'))
            ->withParameters(func_get_args())
            ->getStringResult();
    }

    /**
     * Returns information about the supplied certificate, including fields such
     * as subject name, issuer name, purposes, valid from and valid to dates etc.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-parse.php
     */
    public function x509Parse(
        Cert|OpenSSLCertificate|string $certificate,
        bool $shortNames = true
    ): ArrayResult {
        return (new Call($this, 'x509_parse'))
            ->withParameters(func_get_args())
            ->getArrayResult();
    }

    /**
     * Parses the certificate supplied by certificate and returns an OpenSSLCertificate object for it.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-read.php
     */
    public function x509Read(
        Cert|OpenSSLCertificate|string $certificate
    ): CertResult {
        return (new Call($this, 'x509_read'))
            ->withParameters(func_get_args())
            ->getCertResult();
    }

    /**
     * Verifies that the certificate certificate was signed by the private key corresponding to
     * public key public_key.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-verify.php
     */
    public function x509Verify(
        Cert|OpenSSLCertificate|string $certificate,
        Key|Cert|OpenSSLAsymmetricKey|OpenSSLCertificate|array|string $publicKey
    ): IntResult {
        return (new CallWithNoFailuresExpected($this, 'x509_verify'))
            ->withParameters(func_get_args())
            ->getIntResult();
    }
}
