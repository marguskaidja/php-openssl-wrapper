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

/**
 * @method CSRParam value()
 * @method Key privateKey()
 */
class CSRNew extends Result
{
    protected Key $privateKey;

    protected function init(): void
    {
        $keyIn = $this->inParameters[1];
        $keyOut = $this->outParameters[1];

        if ($keyIn instanceof Key && $keyIn->internal() === $keyOut) {
            /** @var $keyIn Key */
            $this->privateKey = $keyIn;
        } elseif ($keyOut instanceof OpenSSLAsymmetricKey) {
            /** @var $keyIn OpenSSLAsymmetricKey */
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
}
