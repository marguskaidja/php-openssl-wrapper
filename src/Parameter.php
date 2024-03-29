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

use margusk\Accessors\Attributes\Get;
use margusk\Accessors\Accessible;

/**
 * @method Proxy proxy()
 * @method mixed internal()
 */
#[Get]
abstract class Parameter
{
    use Accessible;

    public function __construct(
        protected Proxy $proxy,
        protected mixed $internal
    ) {
    }
}
