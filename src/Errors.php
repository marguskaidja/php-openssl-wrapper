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

/**
 * @method array openSSL()
 * @method array php()
 */
#[Get]
class Errors
{
    use GetSetTrait;

    public function __construct(
        protected array $php,
        protected array $openSSL
    ) {
    }

    public function all(): array
    {
        return array_merge(
            array_column($this->php, 'message'),
            $this->openSSL
        );
    }

    public function hasAny(): bool
    {
        return (count($this->php) > 0) || (count($this->openSSL) > 0);
    }
}
