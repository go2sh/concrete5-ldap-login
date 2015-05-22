<?php defined('C5_EXECUTE') or die('Access denied.'); ?>
<fieldset>
  <legend><?= t("LDAP Server Configuration")?></legend>
  <div class='form-group'>
    <?= $form->label('ldapServerURI', t('LDAP Server URI')) ?>
    <?= $form->text('ldapServerURI', $ldapServerURI) ?>
  </div>
  <div class='form-group'>
    <?= $form->label('ldapBaseDN', t('LDAP Base DN')) ?>
    <?= $form->text('ldapBaseDN', $ldapBaseDN) ?>
  </div>
  <div class='form-group'>
    <?= $form->label('ldapBindDN', t('LDAP Bind DN')) ?>
    <?= $form->text('ldapBindDN', $ldapBindDN) ?>
  </div>
  <div class='form-group'>
    <?= $form->label('ldapBindPassword', t('LDAP Bind Password')) ?>
    <?= $form->password('ldapBindPassword', $ldapBindPassword) ?>
  </div>
  <div class='form-group'>
    <?= $form->label('ldapSearchFilter', t('LDAP Search Filter')) ?>
    <?= $form->text('ldapSearchFilter', $ldapSearchFilter) ?>
  </div>
</fieldset>
<fieldset>
  <legend>Yubikey OTP Configuration</legend>
  <div class='form-group'>
    <?= $form->label('yubikeyEnabled', t('Enable Yubikey OTP')) ?>
    <?= $form->checkbox('yubikeyEnabled', 1, $yubikeyEnabled) ?>
  </div>
  <div id="yubikey-options" style="display: <?= $yubikeyEnabled ? 'block' : 'none' ?>;">
    <div class='form-group'>
      <?= $form->label('yubikeyClientID', t('Yubikey Client ID')) ?>
      <?= $form->text('yubikeyClientID', $yubikeyClientID) ?>
    </div>
    <div class='form-group'>
      <?= $form->label('yubikeySecretKey', t('Yubikey Secret Key')) ?>
      <?= $form->password('yubikeySecretKey', $yubikeySecretKey) ?>
    </div>
    <div class='form-group'>
      <?= $form->label('yubikeyServerURI', t('Yubikey Verify URI')) ?>
      <?= $form->text('yubikeyServerURI', $yubikeyServerURI) ?>
    </div>
    <div class='form-group'>
      <?= $form->label('yubikeyLDAPAtttribute', t('Yubikey Key ID LDAP Attribute')) ?>
      <?= $form->text('yubikeyLDAPAtttribute', $yubikeyLDAPAtttribute) ?>
    </div>
    <div class='form-group'>
      <?= $form->label('yubikeyAllowEmptyKey', t('Allow login with no Yubikey specified')) ?>
      <?= $form->checkbox('yubikeyAllowEmptyKey', 1, $yubikeyAllowEmptyKey) ?>
    </div>
  </div>
  <script>
    $('#yubikeyEnabled').click(function(){
      if ( $(this).is(':checked') )
        $('#yubikey-options').show()
      else
        $('#yubikey-options').hide();
    });
    </script>
</fieldset>
