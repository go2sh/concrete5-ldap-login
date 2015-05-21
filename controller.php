<?php
namespace Concrete\Package\LdapLogin;

use Concrete\Core\Package\Package;
use Concrete\Core\Authentication\AuthenticationType;


defined('C5_EXECUTE') or die(_('Access denied.'));

class Controller extends Package {

  protected $pkgHandle = 'ldap_login';
  protected $appVersionRequired = '5.7.2';
  protected $pkgVersion = '1.0';

  public function getPackageDescription() {
    return t("Add LDAP login functionality.");
  }

  public function getPackageName() {
    return "LDAP Login";
  }

  public function install() {
    $pkg = parent::install();
    $at = AuthenticationType::add('ldap','LDAP',0,$pkg);
  }

  public function uninstall() {
    $at = AuthenticationType::getByHandle('ldap');
    $at->delete();
    parent::uninstall();
  }

}
?>
