<?php

namespace Genj\SsoServerBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 *
 * @package Genj\SsoServerBundle\DependencyInjection
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('genj_sso_server');

        $rootNode
            ->children()
                ->scalarNode('authentication_provider_key')->defaultValue('secured_area')->end()
                ->scalarNode('sso_server_class')->defaultValue('Genj\SsoServerBundle\Sso\Server')->end()
                ->scalarNode('attach_file_path')->isRequired()->end()
                ->arrayNode('brokers')
                    ->prototype('array')
                        ->children()
                            ->scalarNode('secret')->isRequired()->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}