<?php

namespace Kanboard\Plugin\CASAuth;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\Role;
use Kanboard\Core\Translator;
use Kanboard\Plugin\CASAuth\Auth\CasAuthProvider;

class Plugin extends Base
{
    public function initialize()
    {
        $this->authenticationManager->register(new CasAuthProvider($this->container));

        $this->template->hook->attach('template:header:dropdown', 'CASAuth:header/logout');
    }

    public function onStartup()
    {
        Translator::load($this->languageModel->getCurrentLanguage(), __DIR__.'/Locale');
    }

    public function getPluginName()
    {
        return 'CAS Authentication';
    }

    public function getPluginDescription()
    {
        return t('Use CAS as authentication provider');
    }

    public function getPluginAuthor()
    {
        return 'Jamaïca Servier/Manuel Raposo';
    }

    public function getPluginVersion()
    {
        return '1.0.2';
    }

    public function getPluginHomepage()
    {
        return 'https://github.com/eSkiSo/CASAuth';
    }

    public function getCompatibleVersion()
    {
        return '>=1.2.5';
    }
}
