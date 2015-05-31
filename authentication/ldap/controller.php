<?php
namespace Concrete\Package\LdapLogin\Authentication\Ldap;

use Library\Authentication\AuthYubico;
use Concrete\Core\Authentication\AuthenticationTypeController;

use Config;
use Loader;
use User;
use UserInfo;


class Controller extends AuthenticationTypeController {

  public function getHandle() {
    return 'ldap';
  }

  public function view() {

  }

  public function edit()
  {
    $this->set('form', Loader::helper('form'));
    $this->set('ldapServerURI', Config::get('auth.ldap.ldapServerURI', ''));
    $this->set('ldapBaseDN', Config::get('auth.ldap.ldapBaseDN', ''));
    $this->set('ldapBindDN', Config::get('auth.ldap.ldapBindDN', ''));
    $this->set('ldapBindPassword', Config::get('auth.ldap.ldapBindPassword', ''));
    $this->set('ldapSearchFilter', Config::get('auth.ldap.ldapSearchFilter', ''));
    $this->set('usernameLDAPAttribute', Config::get('auth.ldap.usernameLDAPAttribute', 'uid'));
    $this->set('allowRegistration', Config::get('auth.ldap.allowRegistration', false));
    $this->set('yubikeyEnabled', Config::get('auth.ldap.yubikeyEnabled', false));
    $this->set('yubikeyClientID', Config::get('auth.ldap.yubikeyClientID', ''));
    $this->set('yubikeySecretKey', Config::get('auth.ldap.yubikeySecretKey', ''));
    $this->set('yubikeyServerURI', Config::get('auth.ldap.yubikeyServerURI', ''));
    $this->set('yubikeyLDAPAtttribute', Config::get('auth.ldap.yubikeyLDAPAtttribute', 'pager'));
    $this->set('yubikeyAllowEmptyKey', Config::get('auth.ldap.yubikeyAllowEmptyKey', false));

  }

  public function saveAuthenticationType($args)
  {
    Config::save('auth.ldap.ldapServerURI',$args['ldapServerURI']);
    Config::save('auth.ldap.ldapBaseDN',$args['ldapBaseDN']);
    Config::save('auth.ldap.ldapBindDN',$args['ldapBindDN']);
    Config::save('auth.ldap.ldapBindPassword',$args['ldapBindPassword']);
    Config::save('auth.ldap.ldapSearchFilter',$args['ldapSearchFilter']);
    Config::save('auth.ldap.usernameLDAPAttribute',$args['usernameLDAPAttribute']);
    Config::save('auth.ldap.allowRegistration',$args['allowRegistration']);
    Config::save('auth.ldap.yubikeyEnabled',$args['yubikeyEnabled']);
    Config::save('auth.ldap.yubikeyClientID',$args['yubikeyClientID']);
    Config::save('auth.ldap.yubikeySecretKey',$args['yubikeySecretKey']);
    Config::save('auth.ldap.yubikeyServerURI',$args['yubikeyServerURI']);
    Config::save('auth.ldap.yubikeyLDAPAtttribute',$args['yubikeyLDAPAtttribute']);
    Config::save('auth.ldap.yubikeyAllowEmptyKey',$args['yubikeyAllowEmptyKey']);
  }

  public function getAuthenticationTypeIconHTML() {
    return '<i class="fa fa-folder"></i>';
  }

  private function __connect() {
    if (!is_object($this->ldapConn)) {
      $this->ldapConn = ldap_connect(Config::get('auth.ldap.ldapServerURI',''))
        or die(t('Connection to LDAP Server failed.'));
      ldap_set_option($this->ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
      $bindDN = Config::get('auth.ldap.ldapBindDN', '');
      $bindPW = Config::get('auth.ldap.ldapBindPassword', '');
      if ($bindDN) {
        $this->ldapBind = ldap_bind($this->ldapConn,$bindDN,$bindPW);
      } else {
        $this->ldapBind = ldap_bind($this->ldapConn);
      }
      if (!$this->ldapBind) {
        throw new \Exception(t("Binding with LDAP Server failed."));
      }
    }
  }

  private function yubikeyIsOtp($otp) {
    if (!preg_match("/^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{44}$/", $otp)) {
      return FALSE;
    }
    return TRUE;
  }


  public function authenticate() {
    $valc = Loader::helper('concrete/validation');
    $vals = Loader::helper('validation/strings');
    $post = $this->post();

    //Check for empty username and password
    if (empty($post['uName']) || empty($post['uPassword'])) {
      throw new \Exception(t('Please provide both username and password.'));
    }

    $uName = $post['uName'];
    $uPassword = $post['uPassword'];
    $uOTP = $post['uOTP'];

    //Prepare ldap search
    if (Config::get('concrete.user.registration.email_registration')) {
      //Validate email
      if(!$vals->email($uName)) {
        throw new \Exception(t('Invalid username or password.'));
      }
      $userFilter = "(mail=".$uName.")";
    }
    else {
      //Validate username
      if(!$valc->username($uName)) {
        throw new \Exception(t('Invalid username or password.'));
      }
      $userFilter = "(".Config::get('auth.ldap.usernameLDAPAttribute','uid')."=".$uName.")";
    }
    $searchFilter = "(&".$userFilter.Config::get('auth.ldap.ldapSearchFilter', "").")";

    //Connect to ldap, do the search and then auth the user
    $this->__connect();
    $searchResult = ldap_search($this->ldapConn,Config::get('auth.ldap.ldapBaseDN', ''),
      $searchFilter);
    if (ldap_count_entries($this->ldapConn,$searchResult)!=1) {
      throw new \Exception(t('Invalid username or password.'));
    }
    $entry = ldap_first_entry($this->ldapConn,$searchResult);
    //get it here because of the new bind.
    if (Config::get('auth.ldap.yubikeyEnabled',false)) {
      $yubikeys = ldap_get_values($this->ldapConn,$entry,Config::get('auth.ldap.yubikeyLDAPAtttribute','pager'));
    }
    $attrs = ldap_get_attributes($this->ldapConn,$entry);
    if (in_array("mail",$attrs)) {
      $mails = ldap_get_values($this->ldapConn,$entry,"mail");
    }
    if (in_array(Config::get('auth.ldap.usernameLDAPAttribute','uid'),$attrs)) {
      $uids = ldap_get_values($this->ldapConn,$entry,Config::get('auth.ldap.usernameLDAPAttribute','uid'));
    }

    //Authenticate the user
    $user_bind = ldap_bind($this->ldapConn,ldap_get_dn($this->ldapConn,$entry),$uPassword);
    if (!$user_bind) {
      throw new \Exception(t('Invalid username or password.'));
    }
    ldap_close($this->ldapConn);

    //Start yubikey two-factor
    if (Config::get('auth.ldap.yubikeyEnabled',false)) {
      if (!empty($yubikeys)) {
        if (!$this->yubikeyIsOtp($uOTP)) {
          throw new \Exception(t('Invalid username or password.'));
        }

        //Check the otp and then the key id
        $clientID = Config::get('auth.ldap.yubikeyClientID','');
        $secretKey = Config::get('auth.ldap.yubikeySecretKey','');
        $https = 1;
        $yubi = new AuthYubico($clientID,$secretKey,$https);
        $auth = $yubi->verify($uOTP);
        if (\PEAR::isError($auth)) {
          throw new \Exception(t('Invalid username or password.'));
        }
        $foundKey = 0;
        foreach ($yubikeys as $yubikey) {
          if (strcmp($yubikey, substr($uOTP,0,12))==0) {
            $foundKey = 1;
            break;
          }
        }
        if (!$foundKey) {
          throw new \Exception(t('Invalid username or password.'));
        }
      } else {
        if (!Config::get('auth.ldap.yubikeyAllowEmptyKey',false)) {
          throw new \Exception(t('Yubikey is required to login.'));
        }
      }
    }

    if (Config::get('concrete.user.registration.email_registration')) {
      $userInfo = UserInfo::getByUserName($uName);
    }
    else {
      $userInfo = UserInfo::getByEmail($uName);
    }
    if (!is_object($userInfo)) {
      if (Config::get('auth.ldap.allowRegistration',false)) {
        if (empty($uids)) {
          throw new \Exception(t('No user id found in the directory.'));
        }
        if (empty($mails)) {
          throw new \Exception(t('No email address found in the directory.'));
        }
        $data = array();
        $data['uName'] = $uids[0];
        $data['uPassword'] = \Illuminate\Support\Str::random(256);
        $data['uEmail'] = $mails[0];
        $data['uIsValidated'] = 1;

        $userInfo = UserInfo::add($data);
        if (!$userInfo) {
          throw new Exception(t('Unable to create new account.'));
        }
      }
      else {
        throw new \Exception(t('Invalid username or password.'));
      }
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
      //This is a little tricky. Use concrete AT to create a cookie.
      $user->setAuthTypeCookie('concrete');
    }
    return $user;
  }

  public function deauthenticate(User $u) {

  }

  public function isAuthenticated(User $u) {
    return $u->isLoggedIn();
  }

  public function buildHash(User $u) {
    return "";
  }

  public function verifyHash(User $u, $hash) {
    return false;
  }
}
?>
