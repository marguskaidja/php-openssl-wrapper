<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Result;

use margusk\OpenSSL\Wrapper\Exception\RuntimeException;
use margusk\OpenSSL\Wrapper\Parameter\AsymmetricKey as Key;
use margusk\OpenSSL\Wrapper\Parameter\CSR as CSRParam;
use margusk\OpenSSL\Wrapper\Result;
use OpenSSLAsymmetricKey;

class CSRNew extends Result
{
    protected ?Key $privateKey = null;

    public function value(): CSRParam
    {
        return $this->value;
    }

    public function privateKey(): Key
    {
        if (null === $this->privateKey) {
            $keyIn = $this->inParameters[1];
            $keyOut = $this->outParameters[1];

            if ($keyIn instanceof Key && $keyIn->internal() === $keyOut) {
                $this->privateKey = $keyIn;
            } elseif ($keyOut instanceof OpenSSLAsymmetricKey) {
                $this->privateKey = new Key($this->value()->proxy(), $keyOut);
            } else {
                throw new RuntimeException(
                    sprintf(
                        'expecting second out-parameter to be instanceof of "%s"',
                        OpenSSLAsymmetricKey::class
                    )
                );
            }
        }

        return $this->privateKey;
    }
}