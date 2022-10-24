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

use function margusk\Utils\Warbsorber;
use Closure;
use Throwable;
use margusk\OpenSSL\Wrapper\Exception\InvalidArgumentException;
use margusk\OpenSSL\Wrapper\Exception\OpenSSLCallFailedException;
use margusk\OpenSSL\Wrapper\Util;
use ReflectionFunction;

class Options
{
    protected array $failureHandlers = [];

    public function registerFailureHandler(string $pattern, Closure $cb): static
    {
        $cloned = clone $this;
        $cloned->registerFailureHandlerInternal($pattern, $cb);
        return $cloned;
    }

    public function registerFailureHandlers(array $callbacks): static
    {
        $cloned = clone $this;
        foreach ($callbacks as $pattern => $cb) {
            $cloned->registerFailureHandlerInternal($pattern, $cb);
        }
        return $cloned;
    }

    protected function registerFailureHandlerInternal(string $pattern, Closure $cb): void
    {
        $rf = new ReflectionFunction($cb);

        // Check callback's 1-st parameter
        if ($rf->getNumberOfRequiredParameters() > 1) {
            throw new InvalidArgumentException(
                sprintf('callback must not require more than 1 parameter')
            );
        } else {
            $argType = $rf->getParameters()[0]?->getType();

            if (null !== $argType && OpenSSLCallFailedException::class !== $argType->getName()) {
                throw new InvalidArgumentException(
                    sprintf(
                        'callback\'s first parameter must accept "%s"',
                        OpenSSLCallFailedException::class
                    )
                );
            }
        }

        // Check callback's return type
        if (Throwable::class !== $rf->getReturnType()?->getName()) {
            throw new InvalidArgumentException(
                sprintf(
                    'callback\'s return value must be instance of "%s"',
                    Throwable::class
                )
            );
        }

        $regexPrefix = 'regex:';

        if (0 === strcasecmp(substr($pattern, 0, strlen($regexPrefix)), $regexPrefix)) {
            // Test PREG pattern
            $pattern = substr($pattern, strlen($regexPrefix));
            $patternEx = "|".$pattern."|i";

            $errors = Warbsorber(function () use ($patternEx) {
                preg_match($patternEx, "");
            });

            if (count($errors)) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Invalid REGEX pattern "%s": %s',
                        $pattern,
                        $errors[0]->errStr
                    )
                );
            }

            $this->failureHandlers[] = [
                'type'    => 'regex',
                'pattern' => $patternEx,
                'cb'      => $cb
            ];
        } else {
            $this->failureHandlers[] = [
                'type'    => 'compare',
                'pattern' => $pattern,
                'cb'      => $cb
            ];
        }
    }

    public function invokeFailureHandler(OpenSSLCallFailedException $exception): Throwable
    {
        $funcName = $exception->funcName();

        foreach ($this->failureHandlers as $e) {
            if (('regex' === $e['type'] && preg_match($e['pattern'], $funcName))
                || 0 === strcasecmp($funcName, $e['pattern'])
            ) {
                return $e['cb']($exception);
            }
        }

        return $exception;
    }
}
