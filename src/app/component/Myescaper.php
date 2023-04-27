<?php
// escaper for sanitizing the inputs
use Phalcon\Escaper;

class Myescaper
{
    public $escaper;
    public function __construct()
    {
        $this->escaper = new Escaper();
    }
    public function sanitize($param)
    {
        return $this->escaper->escapeHtml($param);
    }
}
