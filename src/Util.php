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

use Closure;

class Util
{
    public static function catchPHPErrors(Closure $closure): array
    {
        $errors = [];

        // Setup our error handler
        $prevHandler = set_error_handler(
            function ($severity, $message, $filename, $lineno) use (&$errors) {
                $errors[] = [
                    'severity' => $severity,
                    'message'  => $message,
                    'filename' => $filename,
                    'lineno'   => $lineno,
                ];

                return true;
            }
        );

        // Execute and catch all possible errors
        $closure();

        // Restore previous error handler
        set_error_handler($prevHandler);

        return $errors;
    }
}
