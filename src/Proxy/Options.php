<?php

/**
 * This file is part of the openssl-wrapper package.
 *
 * @author  Margus Kaidja <margusk@gmail.com>
 * @link    https://github.com/marguskaidja/php-openssl-wrapper
 * @license http://www.opensource.org/licenses/mit-license.php MIT (see the LICENSE file)
 */

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Proxy;

use Closure;
use Throwable;
use margusk\OpenSSL\Wrapper\Exception\InvalidArgumentException;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Util;
use ReflectionFunction;

class Options
{
    protected array $onCallFailed = [];

    public function onCallFailed(string $pattern, Closure $cb): static
    {
        if (Throwable::class !== (new ReflectionFunction($cb))->getReturnType()?->getName()) {
            throw new InvalidArgumentException(
                sprintf(
                    "closure's return value must implement %s",
                    Throwable::class
                )
            );
        }

        $regexPrefix = 'regex:';

        if (0 === strcasecmp(substr($pattern, 0, strlen($regexPrefix)), $regexPrefix)) {
            // Test PREG pattern
            $pattern = substr($pattern, strlen($regexPrefix));
            $patternEx = "|".$pattern."|i";

            $errors = Util::catchPHPErrors(function () use ($patternEx) {
                $result = preg_match($patternEx, "");
            });

            if (count($errors)) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Invalid REGEX pattern "%s": %s',
                        $pattern,
                        $errors[0]['message']
                    )
                );
            }

            $this->onCallFailed[] = [
                'type'    => 'regex',
                'pattern' => $patternEx,
                'cb'      => $cb
            ];
        } else {
            $this->onCallFailed[] = [
                'type'    => 'compare',
                'pattern' => $pattern,
                'cb'      => $cb
            ];
        }

        return $this;
    }

    public function callFailed(OpenSSLCallFailedException $exception): Throwable
    {
        $funcName = $exception->funcName();

        foreach ($this->onCallFailed as $e) {
            if (('regex' === $e['type'] && preg_match($e['pattern'], $funcName))
                || 0 === strcasecmp($funcName, $e['pattern'])
            ) {
                return $e['cb']($exception);
            }
        }

        return $exception;
    }
}
