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
 * @method bool strongResult()
 */
class RandomPseudoBytes extends String_
{
    protected bool $strongResult;

    protected function init(): void
    {
        $this->strongResult = $this->outParameters[1];
    }
}
