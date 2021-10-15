<?php

declare(strict_types=1);

namespace margusk\OpenSSL\Wrapper;

class Errors
{
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

    public function openSSL(): array
    {
        return $this->openSSL;
    }

    public function php(): array
    {
        return $this->php;
    }
}