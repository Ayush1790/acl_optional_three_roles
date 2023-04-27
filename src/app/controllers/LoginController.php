<?php

use Phalcon\Mvc\Controller;
use handler\Aware\Aware;
use handler\Listener\Listener;
use Phalcon\Events\Manager as EventsManager;
// Login Controller class
class LoginController extends Controller
{
    public function indexAction()
    {
        // redirect to view
        $eventsManager = new EventsManager();
        $componant = new Aware();
        $componant->setEventsManager($eventsManager);
        $eventsManager->attach(
            'test',
            new Listener()
        );
        $componant->process();
    }
    public function loginAction()
    {
        $this->view->msg = 0;
        $data = $this->request->getPost();
        if (empty($data['email']) || empty($data['pswd'])) {
            $this->view->msg = 0;
            if (empty($data['email']) && empty($data['pswd'])) {
                $this->logger
                    ->excludeAdapters(['signup'])
                    ->info("email is empty and password is empty");
            } elseif (empty($data['email'])) {
                $this->logger
                    ->excludeAdapters(['signup'])
                    ->info("email is empty ");
            } else {
                $this->logger
                    ->excludeAdapters(['signup'])
                    ->info("password is empty ");
            }
        } else {
            $result = Users::findFirst(array("email=?0 and pswd=?1 ", "bind" => array($data['email'], $data['pswd'])));
            if ($data['pswd'] == $result->pswd && $data['email'] == $result->email) {
                $eventsManager = new EventsManager();
                $componant = new Aware();
                $componant->setEventsManager($eventsManager);
                $eventsManager->attach(
                    'session',
                    new Listener()
                );
                $componant->process();
                $this->cookies->set("isLogin", true, time() + 86400);
                $this->view->msg = 1;
            } else {
                $this->logger
                    ->excludeAdapters(['signup'])
                    ->info("Wrong emailid or password");
            }
        }
    }
}
