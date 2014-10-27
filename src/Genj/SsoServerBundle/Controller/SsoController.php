<?php

namespace Genj\SsoServerBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Genj\SsoServerBundle\Sso\Server;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Class SsoController
 *
 * @package Genj\SsoServerBundle\Controller
 */
class SsoController extends Controller
{
    /**
     * @param Request $request
     *
     * @throws \Symfony\Component\HttpKernel\Exception\NotFoundHttpException
     *
     * @return Response
     */
    public function indexAction(Request $request)
    {
        // Execute controller command
        if ($request->get('cmd')) {
            /**
             * @var Server $server
             */
            $server = $this->get('genj_sso_server.server');

            $command = $request->get('cmd');
            $server->$command();
        } else {
            throw new NotFoundHttpException();
        }

        return new Response('');
    }
}
