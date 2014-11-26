<?php

namespace Genj\SsoServerBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Security;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Bundle\SecurityBundle\Templating\Helper\SecurityHelper;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Genj\SsoServerBundle\Sso\Server;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Http\Authentication\SimpleAuthenticationHandler;

/**
 * Class SsoController
 *
 * @package Genj\SsoServerBundle\Controller
 */
class SsoController extends Controller
{
    /**
     * @return Response
     */
    public function loginAction()
    {
        $server = $this->get('genj_sso_server.server');

        return $server->login();
    }

    /**
     * @return Response
     */
    public function logoutAction()
    {
        $server = $this->get('genj_sso_server.server');

        return $server->logout();
    }

    /**
     * @return Response
     */
    public function infoAction()
    {
        $server = $this->get('genj_sso_server.server');

        return $server->info();
    }

    /**
     * @return Response
     */
    public function attachAction()
    {
        $server = $this->get('genj_sso_server.server');

        return $server->attach();
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function registerAction(Request $request)
    {
        $response = array(
            'status' => 200,
            'data' => $request->request->all()
        );

        return new JsonResponse($response);
    }

    /**
     * @return mixed
     */
    public function validateAuthTokenAction()
    {
        $server = $this->get('genj_sso_server.server');

        return $server->validateAuthToken();
    }
}
