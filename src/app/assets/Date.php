<?php
// class for getting current date and time
namespace date;

class Date
{
    public function getDate()
    {
        date_default_timezone_set("Asia/Calcutta");
        return date('Y-m-d h:i:sa');
    }
}
