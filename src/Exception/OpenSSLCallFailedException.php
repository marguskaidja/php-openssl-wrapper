<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Exception;

use margusk\Accessors\Attributes\Get;
use margusk\Accessors\Accessible;
use margusk\OpenSSL\Wrapper\Errors;
use RuntimeException;

/**
 * @method string   funcName() Returns native openssl_* function causing the failure
 * @method Errors   errors() Returns Errors object encapsulating PHP/openSSL error/warning messages during the openssl_* function call
 * @method mixed    nativeResult() Returns the native result from the failed openssl_* function
 */
#[Get]
class OpenSSLCallFailedException extends RuntimeException implements Contract
{
    use Accessible;

    public function __construct(
        protected string $funcName,
        protected Errors $errors,
        protected mixed $nativeResult
    ) {
        $message = $funcName.'(): '.implode("\n", $errors->all());
        parent::__construct($message);
    }
}
