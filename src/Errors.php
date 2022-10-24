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
use margusk\Utils\Warbsorber\Entry;
use margusk\Utils\Warbsorber\Warnings;

/**
 * @property-read array     $openSSL Errors/warnings reported by linked openSSL library
 * @property-read Warnings  $php Errors/warnings reported by PHP engine
 *
 * @method array openSSL()  Returns errors/warnings reported by linked openSSL library
 * @method array php()      Returns errors/warnings reported by PHP engine
 */
#[Get]
class Errors
{
    use GetSetTrait;

    public function __construct(
        protected Warnings $php,
        protected array $openSSL
    ) {
    }

    public function all(): array
    {
        return array_merge(
            array_map(
                fn(Entry $e) => $e->errStr,
                $this->php->getArrayCopy()
            ),
            $this->openSSL
        );
    }

    public function hasAny(): bool
    {
        return (count($this->php) > 0) || (count($this->openSSL) > 0);
    }
}
