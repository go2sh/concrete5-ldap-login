<?php
defined('C5_EXECUTE') or die('Access denied.');
$form = Loader::helper('form');
$pkg = Package::getByHandle('ldap_login');
$path = $pkg->getRelativePath()."/authentication/ldap/yubiright_16x16.gif"
?>

<form method='post'
      action='<?= View::url('/login', 'authenticate', $this->getAuthenticationTypeHandle()) ?>'>
  <div class="form-group concrete-login">
    <span><?= t('Sign in with a LDAP account.') ?> </span>
    <hr>
  </div>
  <div class="form-group">
    <input name="uName" class="form-control col-sm-12"
           placeholder="<?= Config::get('concrete.user.registration.email_registration') ? t('Email Address') : t('Username')?>" />
    <label>&nbsp;</label>
    <input name="uPassword" class="form-control" type="password"
           placeholder="<?=t('Password')?>" />
    <?php if (\Config::get('auth.ldap.yubikeyEnabled',false)) { ?>
      <label>&nbsp;</label>
      <div class="input-group">
        <div class="input-group-addon"><img src="<?= $path ?>" /></div>
        <input name="uOTP" class="form-control" type="password"
               placeholder="<?=t('OTP')?>" />
      </div>
    <?php } ?>
    <div class="checkbox">
      <label style="font-weight:normal">
        <input type="checkbox" name="uMaintainLogin" value="1">
        <?= t('Stay signed in for two weeks') ?>
      </label>
    </div>
  </div>

  <?php
  if (isset($locales) && is_array($locales) && count($locales) > 0) {
  ?>
    <div class="form-group">
      <label for="USER_LOCALE" class="control-label"><?= t('Language') ?></label>
      <?= $form->select('USER_LOCALE', $locales) ?>
    </div>
  <?php
  }
  ?>

  <div class="form-group">
    <button class="btn btn-primary"><?= t('Log in') ?></button>
  </div>

  <script type="text/javascript">
    document.querySelector('input[name=uName]').focus();
  </script>

  <?php Loader::helper('validation/token')->output('login_' . $this->getAuthenticationTypeHandle()); ?>
</form>
