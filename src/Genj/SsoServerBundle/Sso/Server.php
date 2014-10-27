<?php

namespace Genj\SsoServerBundle\Sso;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage;
use Symfony\Component\HttpFoundation\Session\Storage\PhpBridgeSessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Webservice\UserBundle\Form\Handler\LoginFormHandler;

/**
 * Class Server
 *
 * @package Genj\SsoServerBundle\Sso
 */
class Server
{
    /**
     * Path to link files. Set this to use link files instead of symlinks.
     * Don't forget to clean up old session files once in a while.
     *
     * @var string
     */
    public $linksPath;

    /**
     * Flag to indicate the sessionStart has been called
     * @var boolean
     */
    protected $started=false;

    /**
     * Information of the brokers.
     * This should be data in a database.
     *
     * @var array
     */
    protected static $brokers = array(
        'ALEX' => array('secret'=>"abc123"),
        'BINCK' => array('secret'=>"xyz789"),
        'UZZA' => array('secret'=>"rino222"),
        'AJAX' => array('secret'=>"amsterdam"),
        'LYNX' => array('secret'=>"klm345"),
    );

    /**
     * Information of the users.
     * This should be data in a database.
     *
     * @var array
     */
    protected static $users = array(
        'jan' => array('password'=>"jan1", 'fullname'=>"Jan Smit", 'email'=>"jan@smit.nl"),
        'peter' => array('password'=>"peter1", 'fullname'=>"Peter de Vries", 'email'=>"peter.r.de-vries@sbs.nl"),
        'bart' => array('password'=>"bart1", 'fullname'=>"Bart de Graaf", 'email'=>"graaf@bnn.info"),
        'henk' => array('password'=>"henk1", 'fullname'=>"Henk Westbroek", 'email'=>"henk@amsterdam.com"),
        'nico.kaag@genj.nl' => array('password'=>"Tester", 'fullname'=>"Nico Kaag", 'email'=>"nico.kaag@genj.nl")
    );

    /**
     * The current broker
     * @var string
     */
    protected $broker = null;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var null|\Symfony\Component\HttpFoundation\Session\SessionInterface
     */
    protected $session;

    /**
     * @var LoginFormHandler
     */
    protected $loginFormHandler;

    /**
     * Class constructor
     *
     * @param Request $request
     * @param LoginFormHandler $loginFormHandler
     */
    public function __construct(Request $request, LoginFormHandler $loginFormHandler)
    {
        $this->request = $request;
        $this->session = $request->getSession();

        $this->loginFormHandler = $loginFormHandler;

//        if (!function_exists('symlink')) {
            $this->linksPath = '/webservers/webservice/app/var/links/';
//        }
    }

    /**
     * Start session and protect against session hijacking
     */
    protected function sessionStart()
    {
        $this->session->getMetadataBag()->getStorageKey();
        if ($this->started) {
            return;
        }
        $this->started = true;

        // Broker session
        $matches = null;

//        var_dump($this->session->getName());

        if ($this->request->get($this->session->getName())
            && preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->request->get($this->session->getName()), $matches)) {
            $sid = $this->request->get($this->session->getName());

            if (isset($this->linksPath) && file_exists($this->linksPath . $sid)) {
                $this->session->setId(file_get_contents($this->linksPath . $sid));
                $this->session->migrate();
//                $this->session->set($this->session->getName(), "");
                setcookie($this->session->getName(), "", 1);
            } else {
                $this->session->start();
            }

            if (!$this->session->get('client_addr')) {
                $this->session->invalidate();
                $this->fail("Not attached");
            }

            if ($this->generateSessionId($matches[1], $matches[2], $this->session->get('client_addr')) != $sid) {
                $this->session->invalidate();
                $this->fail("Invalid session id");
            }

            $this->broker = $matches[1];

            return;
        }

        // User session
        $this->session->start();
        if ($this->session->get('client_addr')
            && $this->session->get('client_addr') != $this->request->getClientIp()) {
            $this->session->migrate(true);
        }

        if (!$this->session->get('client_addr')) {
            $this->session->set('client_addr', $this->request->getClientIp());
        }
    }

    /**
     * Generate session id from session token
     *
     * @param string $broker
     * @param string $token
     * @param null $clientAddr
     *
     * @return null|string
     */
    protected function generateSessionId($broker, $token, $clientAddr=null)
    {
        if (!isset(self::$brokers[$broker])) {
            return null;
        }

        if (!isset($clientAddr)) {
            $clientAddr = $this->request->getClientIp();
        }

        return "SSO-{$broker}-{$token}-" . md5('session' . $token . $clientAddr . self::$brokers[$broker]['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $broker
     * @param string $token
     *
     * @return null|string
     */
    protected function generateAttachChecksum($broker, $token)
    {
        if (!isset(self::$brokers[$broker])) {
            return null;
        }

        return md5('attach' . $token . $this->request->getClientIp() . self::$brokers[$broker]['secret']);
    }

    /**
     * Authenticate
     */
    public function login()
    {
        $this->sessionStart();

        if (!$this->request->get('username')) {
            $this->failLogin("No user specified");
        }
        if (!$this->request->get('password')) {
            $this->failLogin("No password specified");
        }

        if (!$this->loginFormHandler->authenticateUser($this->request->get('username'), $this->request->get('password'), 'quest')) {
            $this->failLogin("Incorrect credentials");
        }

//        if (!isset(self::$users[$this->request->get('username')])
//            || self::$users[$this->request->get('username')]['password'] != $this->request->get('password')) {
//            $this->failLogin("Incorrect credentials");
//        }

        $this->session->set('user', $this->request->get('username'));
        $this->info();
    }

    /**
     * Log out
     */
    public function logout()
    {
        $this->sessionStart();
        $this->session->remove('user');
        echo 1;
    }


    /**
     * Attach a user session to a broker session
     */
    public function attach()
    {
        $this->sessionStart();

        if (!$this->request->get('broker')) {
            $this->fail("No broker specified");
        }
        if (!$this->request->get('token')) {
            $this->fail("No token specified");
        }
        if (!$this->request->get('checksum')
            || $this->generateAttachChecksum($this->request->get('broker'), $this->request->get('token')) != $this->request->get('checksum')) {
            $this->fail("Invalid checksum");
        }

        if (!isset($this->linksPath)) {
            $link = "/sess_" . $this->generateSessionId($this->request->get('broker'), $this->request->get('token'));
            if (session_save_path()) {
                $link = session_save_path() . $link;
            } else {
                $link = sys_get_temp_dir() . $link;
            }

            if (!file_exists($link)) {
                $attached = symlink('sess_' . $this->session->getId(), $link);
            }
            if (!$attached) {
                trigger_error("Failed to attach; Symlink wasn't created.", E_USER_ERROR);
            }
        } else {
            $link = "{$this->linksPath}/" . $this->generateSessionId($this->request->get('broker'), $this->request->get('token'));
            if (!file_exists($link)) {
                $attached = file_put_contents($link, $this->session->getId());
            }
            if (!$attached) {
                trigger_error("Failed to attach; Link file wasn't created.", E_USER_ERROR);
            }
        }

        if ($this->request->get('redirect')) {
            header("Location: " . $_REQUEST['redirect'], true, 307);
            exit;
        }

        // Output an image specially for AJAX apps
        header("Content-Type: image/png");
        readfile("empty.png");
    }

    /**
     * Ouput user information as XML.
     * Doesn't return e-mail address to brokers with security level < 2.
     */
    public function info()
    {
        $this->sessionStart();
        if (!$this->session->get('user')) {
            $this->failLogin("Not logged in");
        }

        echo json_encode(self::$users[$this->session->get('user')]);
    }


    /**
     * An error occured.
     * I would normaly solve this by throwing an Exception and use an exception handler.
     *
     * @param string $message
     */
    protected function fail($message)
    {
        header("HTTP/1.1 406 Not Acceptable");
        echo $message;
        exit;
    }

    /**
     * Login failure.
     * I would normaly solve this by throwing a LoginException and use an exception handler.
     *
     * @param string $message
     */
    protected function failLogin($message)
    {
        header("HTTP/1.1 401 Unauthorized");
        echo $message;
        exit;
    }
}