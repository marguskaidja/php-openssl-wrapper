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

use margusk\Accessors\Accessible;
use margusk\Accessors\Attr\Get;
use margusk\Warbsorber\Entry;
use margusk\Warbsorber\Warnings;

/**
 * @property-read array     $openSSL    Errors/warnings reported by linked openSSL library
 * @property-read Warnings  $php        Errors/warnings reported by PHP engine
 */
#[Get]
class Errors
{
    use Accessible;

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
