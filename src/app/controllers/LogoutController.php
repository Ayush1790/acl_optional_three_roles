<?php

use Phalcon\MVC\Controller;

// logout controller class
class LogoutController extends Controller
{
    public function indexAction()
    {
        if ($this->cookies->get("isLogin")) {
            $this->session->destroy();
            $this->cookies->set("isLogin", false, time() + 86400);
        }
        $this->response->redirect("index");
    }
}
