<?php

namespace Kanboard\Plugin\CASAuth\Auth;

use Kanboard\Core\Base;
use Kanboard\Core\Security\Role;
use Kanboard\Core\Ldap\Client as LdapClient;
use Kanboard\Core\Ldap\ClientException as LdapException;
use Kanboard\Core\Ldap\User as LdapUser;
use Kanboard\Core\Security\PreAuthenticationProviderInterface;
use Kanboard\Plugin\CASAuth\User\CasUserProvider;

/**
 * CAS Authentication Provider
 *
 * @package  auth
 */
class CasAuthProvider extends Base implements PreAuthenticationProviderInterface
{
    /**
     * User properties
     *
     * @access private
     * @var \Kanboard\Plugin\CASAuth\User\CasUserProvider
     */
    private $userInfo = null;

    /**
     * phpCas instance
     *
     * @access protected
     * @var \phpCas
     */
    protected $service;

    /**
     * Get authentication provider name
     *
     * @access public
     * @return string
     */
    public function getName()
    {
        return 'CAS';
    }

    /**
     * Authenticate the user
     *
     * @access public
     * @return boolean
     */
    public function authenticate()
    {
        try {
            $this->getService();
            $this->service->forceAuthentication();
            if ($this->service->checkAuthentication()) {
                $client = LdapClient::connect('adminf32', LDAP_PASSWORD);
                $useri = LdapUser::getUser($client, $this->service->getUser());
                $this->userInfo = $useri;
                return true;
            }
        } catch (Exception $e) {
            $this->logger->error($e->getMessage());
        }
        return false;
    }

    /**
     * Get role from LDAP groups
     *
     * Note: Do not touch the current role if groups are not configured
     *
     * @access public
     * @param  string[] $groupIds
     * @return string
     */
    public function getRole($groupIds)
    {
        if (!(LDAP_GROUP_MANAGER_DN || LDAP_GROUP_ADMIN_DN)) {
            return null;
        }
        // Init with smallest role
        $role = Role::APP_USER ;
        foreach ($groupIds as $groupId) {
            $groupId = strtolower($groupId);

            if ($groupId === strtolower(LDAP_GROUP_ADMIN_DN)) {
                // Highest role found : we can and we must exit the loop
                $role = Role::APP_ADMIN;
                break;
            }

            if ($groupId === strtolower(LDAP_GROUP_MANAGER_DN)) {
                // Intermediate role found : we must continue to loop, maybe admin role after ?
	            $role = Role::APP_MANAGER;
            }
        }
        return $role;
    }

    /**
     * Get user object
     *
     * @access public
     * @return CasUserProvider
     */
    public function getUser()
    {
        return $this->userInfo;
    }

    /**
     * Get CAS service
     *
     * @access public
     */
    public function getService()
    {
        if (empty($this->service)) {
            $protocol = $_SERVER['PROTOCOL'] = isset($_SERVER['HTTPS']) && !empty($_SERVER['HTTPS']) ? 'https' : 'http';
            $this->service = new \phpCAS();
            $this->service->client(CAS_VERSION_2_0, CAS_HOSTNAME, CAS_PORT, CAS_URI, $protocol."://".$_SERVER['HTTP_HOST'], false);
            $this->service->handleLogoutRequests(false);
            $this->service->setNoCasServerValidation();
        }
    }

    /**
     * logout from CAS
     *
     * @access public
     */
    public function logout()
    {
        $this->getService();

        if ($this->service) {
            $this->service->logout();
        }
    }
}
