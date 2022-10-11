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

/**
 * @method array    encryptedKeys()
 * @method string   iv()
 */
class Seal extends String_
{
    protected array $encryptedKeys;
    protected string $iv;

    protected function init(): void
    {
        $this->encryptedKeys = $this->outParameters[2];
        $this->iv = $this->outParameters[5];
    }
}
