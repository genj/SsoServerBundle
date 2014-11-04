<?php

namespace Genj\SsoServerBundle\Sso;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage;
use Symfony\Component\HttpFoundation\Session\Storage\PhpBridgeSessionStorage;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Webservice\UserBundle\Entity\UserRepository;
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
    protected $brokers;

    /**
     * The current broker
     * @var string
     */
    protected $broker = null;

    /**
     * The provider key to use
     * @var string
     */
    protected $authenticationProviderKey;

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
     * @var UserRepository
     */
    protected $userRepository;

    /**
     * @var SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * Class constructor
     *
     * @param Request                        $request
     * @param LoginFormHandler               $loginFormHandler
     * @param UserRepository                 $userRepository
     * @param SecurityContextInterface       $securityContext
     * @param AuthenticationManagerInterface $authenticationManager
     */
    public function __construct(Request $request, LoginFormHandler $loginFormHandler,
                                UserRepository $userRepository, array $config,
                                SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager)
    {
        $this->request          = $request;
        $this->session          = $request->getSession();

        $this->userRepository   = $userRepository;
        $this->loginFormHandler = $loginFormHandler;

        $this->securityContext       = $securityContext;
        $this->authenticationManager = $authenticationManager;

        $this->setConfig($config);

        if (!function_exists('symlink')) {
            $this->linksPath = sys_get_temp_dir();
        }
    }

    /**
     * Start session and protect against session hijacking
     *
     * @return null
     */
    protected function sessionStart()
    {
        if ($this->started) {
            return;
        }
        $this->started = true;

        // Broker session
        $matches = null;


        if ($this->request->get($this->session->getName())
            && preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->request->get($this->session->getName()), $matches)) {
            $sid = $this->request->get($this->session->getName());

            if (isset($this->linksPath) && file_exists($this->linksPath . $sid)) {
                $this->session->setId(file_get_contents($this->linksPath . $sid));
                $this->session->migrate();

                setcookie($this->session->getName(), "", 1);
            } else {
                $this->session->start();
            }

            if (!$this->session->get('client_addr')) {
                $this->session->invalidate();
                $response = $this->fail("Not attached");

                return $response;
            }

            if ($this->generateSessionId($matches[1], $matches[2], $this->session->get('client_addr')) != $sid) {
                $this->session->invalidate();
                $response = $this->fail("Invalid session id");

                return $response;
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
     * @param null   $clientAddr
     *
     * @return null|string
     */
    protected function generateSessionId($broker, $token, $clientAddr=null)
    {
        if (!isset($this->brokers[$broker])) {
            return null;
        }

        if (!isset($clientAddr)) {
            $clientAddr = $this->request->getClientIp();
        }

        return "SSO-{$broker}-{$token}-" . md5('session' . $token . $clientAddr . $this->brokers[$broker]['secret']);
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
        if (!isset($this->brokers[$broker])) {
            return null;
        }

        return md5('attach' . $token . $this->request->getClientIp() . $this->brokers[$broker]['secret']);
    }

    /**
     * Authenticate
     *
     * @return JsonResponse
     */
    public function login()
    {
        $this->sessionStart();

        if (!$this->request->get('username')) {
            $response = $this->failLogin("No user specified");

            return $response;
        }
        if (!$this->request->get('password')) {
            $response = $this->failLogin("No password specified");

            return $response;
        }

        $unauthenticatedToken = new UsernamePasswordToken($this->request->get('username'), $this->request->get('password'), $this->authenticationProviderKey);

        try {
            $authenticatedToken = $this
                ->authenticationManager
                ->authenticate($unauthenticatedToken);

            $this->securityContext->setToken($authenticatedToken);
        } catch (AuthenticationException $failed) {
            // authentication failed
            $response = $this->failLogin("Incorrect credentials");

            return $response;
        }

//        if (!$this->loginFormHandler->authenticateUser($this->request->get('username'), $this->request->get('password'), $this->request->get('brandIdentifier'))) {
//            $response = $this->failLogin("Incorrect credentials");
//
//            return $response;
//        }

        $this->session->set('user', $this->request->get('username'));

        $userData = array(
            'username'        => $this->request->get('username'),
            'brandIdentifier' => $this->request->get('brandIdentifier')
        );

        $status = array('code' => 200, 'message' => 'success');

        return new JsonResponse(array('status' => $status, 'data' => $userData));
    }

    /**
     * Log out
     *
     * @return JsonResponse
     */
    public function logout()
    {
        $this->sessionStart();
        $this->session->remove('user');

        $status = array('code' => 200, 'message' => 'success');

        return new JsonResponse(array('status' => $status));
    }


    /**
     * Attach a user session to a broker session
     *
     * @return RedirectResponse
     * @throws \Exception
     */
    public function attach()
    {
        $this->sessionStart();

        if (!$this->request->get('broker')) {
            $response = $this->fail("No broker specified");

            return $response;
        }
        if (!$this->request->get('token')) {
            $response = $this->fail("No token specified");

            return $response;
        }
        if (!$this->request->get('checksum')
            || $this->generateAttachChecksum($this->request->get('broker'), $this->request->get('token')) != $this->request->get('checksum')) {
            $response = $this->fail("Invalid checksum");

            return $response;
        }

        $fileSystem = new Filesystem();

        if (!isset($this->linksPath)) {
            $link = "/sess_" . $this->generateSessionId($this->request->get('broker'), $this->request->get('token'));
            if (session_save_path()) {
                $link = session_save_path() . $link;
            } else {
                $link = sys_get_temp_dir() . $link;
            }

            if (!$fileSystem->exists($link)) {
                $fileSystem->symlink('sess_' . $this->session->getId(), $link);
                $attached = true;
            }
            if (!$attached) {
                throw new \Exception("Failed to attach; Symlink wasn't created.", E_USER_ERROR);
            }
        } else {
            $link = "{$this->linksPath}/" . $this->generateSessionId($this->request->get('broker'), $this->request->get('token'));
            if (!$fileSystem->exists($link)) {
                $attached = $fileSystem->dumpFile($link, $this->session->getId());
            }
            if (!$attached) {
                throw new \Exception("Failed to attach; Link file wasn't created.", E_USER_ERROR);
            }
        }

        if ($this->request->get('redirect')) {
            return new RedirectResponse($this->request->get('redirect'), 307);
        }
    }

    /**
     * Output user information as XML.
     * Doesn't return e-mail address to brokers with security level < 2.
     *
     * @return JsonResponse
     */
    public function info()
    {
        $this->sessionStart();
        if (!$this->session->get('user')) {
            $response = $this->failLogin("Not logged in");

            return $response;
        }

        $userData = array(
            'username'        => $this->session->get('user'),
            'brandIdentifier' => $this->request->get('brandIdentifier')
        );

        $status = array('code' => 200, 'message' => 'success');

        return new JsonResponse(array('status' => $status, 'data' => $userData));
    }


    /**
     * An error occurred.
     * I would normally solve this by throwing an Exception and use an exception handler.
     *
     * @param string $message
     *
     * @return JsonResponse
     */
    protected function fail($message)
    {
        $status = array('code' => 406, 'message' => 'fail');

        return new JsonResponse(array('status' => $status, 'error' => $message), 406);
    }

    /**
     * Login failure.
     * I would normally solve this by throwing a LoginException and use an exception handler.
     *
     * @param string $message
     *
     * @return JsonResponse
     */
    protected function failLogin($message)
    {
        $status = array('code' => 401, 'message' => 'fail');

        return new JsonResponse(array('status' => $status, 'error' => $message), 401);
    }

    /**
     * @param array $config
     */
    public function setConfig($config)
    {
        $this->brokers                   = $config['brokers'];
        $this->authenticationProviderKey = $config['authentication_provider_key'];
    }
}