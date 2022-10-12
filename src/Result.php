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
use Stringable;

/**
 * @method Errors   warnings()      Returns Errors object encapsulating possible PHP/openSSL warning messages during the openssl_* function call
 * @method array    inParameters()  Returns list of input parameters passed into openssl_* function
 * @method array    outParameters() Returns list of parameters after beeing passed into openssl_* function and beeing possibly modified (e.g. openssl_seal)
 * @method mixed    value()         Returns interpreted return value of openssl_* function
 */
#[Get]
abstract class Result implements Stringable
{
    use GetSetTrait;

    public function __construct(
        protected string $funcName,
        protected array $inParameters,
        protected array $outParameters,
        protected mixed $value,
        protected Errors $warnings,
    ) {
        $this->init();
    }

    protected function init(): void
    {
        // placeholder for extended classes
    }

    public function __toString(): string
    {
        return strval($this->value);
    }
}
