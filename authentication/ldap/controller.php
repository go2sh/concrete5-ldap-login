<?php
namespace Concrete\Package\LdapLogin\Authentication\Ldap;

use Concrete\Core\Authentication\AuthenticationTypeController;
use User;
use UserInfo;
use View;
use Config;
use Loader;
use Exception;


class Controller extends AuthenticationTypeController {

  const YUBIKEY_VERIFY_URL = "http://api.yubico.com/wsapi/2.0/verify";

  public function getHandle() {
    return 'ldap';
  }

  public function view() {

  }

  public function edit()
  {
    $this->set('form', \Loader::helper('form'));
    $this->set('ldapServerURI', \Config::get('auth.ldap.ldapServerURI', ''));
    $this->set('ldapBaseDN', \Config::get('auth.ldap.ldapBaseDN', ''));
    $this->set('ldapBindDN', \Config::get('auth.ldap.ldapBindDN', ''));
    $this->set('ldapBindPassword', \Config::get('auth.ldap.ldapBindPassword', ''));
    $this->set('ldapSearchFilter', \Config::get('auth.ldap.ldapSearchFilter', ''));
    $this->set('yubikeyEnabled',\Config::get('auth.ldap.yubikeyEnabled', false));
    $this->set('yubikeyClientID',\Config::get('auth.ldap.yubikeyClientID', ''));
    $this->set('yubikeySecretKey',\Config::get('auth.ldap.yubikeySecretKey', ''));
    $this->set('yubikeyServerURI',\Config::get('auth.ldap.yubikeyServerURI', ''));
    $this->set('yubikeyAllowEmptyKey',\Config::get('auth.ldap.yubikeyAllowEmptyKey', false));

  }

  public function saveAuthenticationType($args)
  {
    \Config::save('auth.ldap.ldapServerURI',$args['ldapServerURI']);
    \Config::save('auth.ldap.ldapBaseDN',$args['ldapBaseDN']);
    \Config::save('auth.ldap.ldapBindDN',$args['ldapBindDN']);
    \Config::save('auth.ldap.ldapBindPassword',$args['ldapBindPassword']);
    \Config::save('auth.ldap.ldapSearchFilter',$args['ldapSearchFilter']);
    \Config::save('auth.ldap.yubikeyEnabled',$args['yubikeyEnabled']);
    \Config::save('auth.ldap.yubikeyClientID',$args['yubikeyClientID']);
    \Config::save('auth.ldap.yubikeySecretKey',$args['yubikeySecretKey']);
    \Config::save('auth.ldap.yubikeyServerURI',$args['yubikeyServerURI']);
    \Config::save('auth.ldap.yubikeyAllowEmptyKey',$args['yubikeyAllowEmptyKey']);
  }

  public function getAuthenticationTypeIconHTML() {
    return "";
  }

  private function __connect() {
    if (!is_object($this->ldap_conn)) {
      $this->ldap_conn = ldap_connect(\Config::get('auth.ldap.ldapServerURI',''))
        or die(t('Connection to LDAP Server failed.'));
      ldap_set_option($this->ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
      $bindDN = \Config::get('auth.ldap.ldapBindDN', '');
      $bindPW = \Config::get('auth.ldap.ldapBindPassword', '');
      if ($bindDN) {
        $this->ldap_bind = ldap_bind($this->ldap_conn,$bindDN,$bindPW);
      } else {
        $this->ldap_bind = ldap_bind($this->ldap_conn);
      }
      if (!$this->ldap_bind) {
        throw new Exception(t("Binding with LDAP Server failed."));
      }
    }
  }


  public function authenticate() {
    $post = $this->post();
    if (!isset($post['uName']) || !isset($post['uPassword'])) {
      throw new Exception(t('Please provide both username and password.'));
    }
    $uName = $post['uName'];
    $uPassword = $post['uPassword'];
    $this->__connect();
    $search_result = ldap_search($this->ldap_conn,\Config::get('auth.ldap.ldapBaseDN', ''),
      "(uid=$uName)");
    if (ldap_count_entries($this->ldap_conn,$search_result)!=1) {
      throw new \Exception(t('Invalid username or password.'));
    }
    $entry = ldap_first_entry($this->ldap_conn,$search_result);

    $user_bind = ldap_bind($this->ldap_conn,ldap_get_dn($this->ldap_conn,$entry),$uPassword);
    if (!$user_bind) {
      throw new \Exception(t('Invalid username or password.'));
    }
    $userInfo = UserInfo::getByUserName($uName);
    if (!is_object($userInfo)) {
      throw new \Exception(t('Invalid username or password.'));
    }


    $user = User::loginByUserID($userInfo->uID);
    if (!is_object($user) || !($user instanceof User) || $user->isError()) {
      switch ($user->getError()) {
        case USER_SESSION_EXPIRED:
          throw new \Exception(t('Your session has expired. Please sign in again.'));
          break;
        case USER_NON_VALIDATED:
          throw new \Exception(t(
              'This account has not yet been validated. Please check the email associated with this account and follow the link it contains.'));
          break;
        case USER_INVALID:
          if (Config::get('concrete.user.registration.email_registration')) {
            throw new \Exception(t('Invalid email address or password.'));
          } else {
            throw new \Exception(t('Invalid username or password.'));
          }
          break;
        case USER_INACTIVE:
          throw new \Exception(t('This user is inactive. Please contact us regarding this account.'));
          break;
      }
    }
    if ($post['uMaintainLogin']) {
      $user->setAuthTypeCookie('concrete');
    }
    return $user;
  }

  public function deauthenticate(User $u) {

  }

  public function isAuthenticated(User $u) {

  }

  public function buildHash(User $u) {
    return "";
  }

  public function verifyHash(User $u, $hash) {
    return false;
  }
}
?>
