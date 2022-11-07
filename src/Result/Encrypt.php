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
 * @property-read string $tag
 */
class Encrypt extends String_
{
    protected string $tag;

    protected function init(): void
    {
        $this->tag = $this->outParameters[5];
    }
}
