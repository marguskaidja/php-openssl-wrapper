<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper\Exception;

use margusk\OpenSSL\Wrapper\Errors;
use RuntimeException;

class OpenSSLCallFailedException extends RuntimeException implements Contract
{
    public function __construct(
        protected string $funcName,
        protected Errors $errors,
        protected mixed $result
    ) {
        $message = $funcName.'(): '.implode("\n", $errors->all());
        parent::__construct($message, 0, null);
    }

    public function errors(): Errors
    {
        return $this->errors;
    }

    public function result(): mixed
    {
        return $this->result;
    }

    public function funcName(): string
    {
        return $this->funcName;
    }
}
