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

abstract class Result
{
    public function __construct(
        protected string $funcName,
        protected array $inParameters,
        protected array $outParameters,
        protected mixed $value,
        protected Errors $warnings,
    ) {
    }

    public function warnings(): Errors
    {
        return $this->warnings;
    }

    public function inParameters(): array
    {
        return $this->inParameters;
    }

    public function outParameters(): array
    {
        return $this->outParameters;
    }

    abstract public function value(): mixed;

    public function __toString(): string
    {
        return strval($this->value);
    }
}
