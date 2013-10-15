<?php

defined('AJXP_EXEC') or die( 'Access not allowed');

/**
 * Authenticate Fiducial users
 * @package AjaXplorer_Plugins
 * @subpackage Auth
 */
class fiducialAuthDriver extends AbstractAuthDriver
{

    public function init($options)
    {
        parent::init($options);
    }

    public function userExists($login)
    {
        //$this->Intranet_cron();
        $res = $this->Intranet_GetUserByLogin($login);
        return isset($res);
    }

    public function checkPassword($login, $pass, $seed)
    {
        if(empty($pass)) return false;

        $fiducial = $this->Intranet_DirectAuthentication($login, $pass);

        if($fiducial === false){
            //echec auth
            return false;
        }

        if(!$this->Intranet_CanAccess($fiducial['UserId'])){
            //acces interdit
            return false;
        }

        $oldlogin = $this->getLoginByIntranetId($fiducial['UserId']);
        if( $oldlogin && $oldlogin !== $login) {
            AuthService::renameUser($oldlogin, $login);
        }

        $userObject = ConfService::getConfStorageImpl()->createUserObject($login);

        $roles = $this->Intranet_GetRoles($fiducial['UserId']);
        $this->updateIntranetInfos($userObject,$fiducial,$roles);

        return true;
    }

    public function usersEditable()
    {
        return false;
    }

    public function passwordsEditable()
    {
        return false;
    }

    public function listUsers($baseGroup = "/")
    {
        return array();
    }

    public function updateUserObject(&$userObject)
    {
        //if(!isset($_SESSION['fiducial_infos'])) return;
        //$this->updateIntranetInfos($userObject,$_SESSION['fiducial_infos'],$_SESSION['fiducial_roles']);
    }

    //pour userExists()
    private function Intranet_GetUserByLogin($login)
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "userLogin" => $login,
            "loadAllProperties" => false,
            "parameters" => array(
                "UserId" => '0000',
                "ApplicationName" => 'FiduShare',
                "UserName" => __FUNCTION__, // string
                "Language" => '', // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        return $soapClient->User_GetUserByLogin($params)->User_GetUserByLoginResult;
    }

    //pour checkPassword
    private function Intranet_DirectAuthentication($login, $pass)
    {
        $soapClient = new SoapClient($this->getOption("CASWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "login" => $login,
            "sha1" => base64_encode(sha1(base64_encode(sha1($pass,true)).'ghefzljfhlk',true)),
            "salt" => 'ghefzljfhlk'
        );
        $res = $soapClient->DirectAuthenticationSha1Salted($params);
        $res = $res->DirectAuthenticationSha1SaltedResult;

        if($res->Authenticated){
            //auth ok
            return array(
                'Login' => $login,
                'UserId' => $res->UserId,
                'UserName' => $res->UserName,
                'Language' => $res->LanguageCode,
                'Mail' => $res->Mail
            );
        } else {
            //echec auth
            return false;
        }
    }

    //pour checkPassword
    private function Intranet_CanAccess($UserId, $UserName = '', $Language = '')
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "userId" => $UserId,
            "contenuId" => $this->getOption("INTRANETWS_CONTENUID"),
            "parameters" => array(
                "UserId" => $UserId,
                "ApplicationName" => 'FiduShare',
                "UserName" => $UserName, // string
                "Language" => $Language, // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        return $soapClient->User_CanAccessContenuApplicatif($params);
    }

    //pour checkPassword
    private function Intranet_GetRoles($UserId, $UserName = '', $Language = '')
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "userId" => $UserId,
            "contenuId" => $this->getOption("INTRANETWS_CONTENUID"),
            "parameters" => array(
                "UserId" => $UserId,
                "ApplicationName" => 'FiduShare',
                "UserName" => $UserName, // string
                "Language" => $Language, // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        $res = $soapClient->ContenuApplicatif_GetUserRolesForContenu($params)
        ->ContenuApplicatif_GetUserRolesForContenuResult->CRoleApplicatif;
        if (!isset($res)) return array(); //0 role

        $roles = array();
        foreach ($res as $role) {
            $tag = explode("|", $role->Tag,2);
            if (!array_key_exists($tag[0], $roles)) $roles[$tag[0]] = array();
            $roles[$tag[0]][$tag[1]] = array($UserId);
        }
        $this->Intranet_SortRoles($roles);
        return $roles;
    }

    private function getLoginByIntranetId($intranetId)
    {
        $rows = dibi::query("SELECT [login] FROM [ajxp_user_rights] WHERE [repo_uuid] = %s AND [rights] = %s", "intranet.userid", $intranetId);
        return $rows->fetchSingle();
    }

    private function updateIntranetInfos(&$userObject,&$intranetInfos,&$intranetRoles)
    {

        /*if ($userObject->id != $intranetInfos['Login']) {
            rename user needed
        }*/

        $changes = false;
        if (!array_key_exists('intranet.userid', $userObject->rights)) {
            $userObject->rights['intranet.userid'] = $intranetInfos['UserId'];
            $changes = true;
        }

        $confs = array();
        $confs[] = array("core.conf", "USER_DISPLAY_NAME", $intranetInfos['UserName']);
        $confs[] = array("core.conf", "email", $intranetInfos['Mail']);
        $confs[] = array("core.conf", "INTRANET_UserId", $intranetInfos['UserId']);
        //$confs[] = array("core.conf", "INTRANET_UserName", $intranetInfos['UserName']);
        //$confs[] = array("core.conf", "INTRANET_Language", $intranetInfos['Language']);

        $defaultvalue = array(
            'FILE_MAX_EXPIRATION' => 15,
            'FILE_MAX_DOWNLOAD' => 10,
            'PURGE_AFTER' => 30,
            'DEFAULT_QUOTA' => 100,
            'UPLOAD_MAX_SIZE' => 20
        );

        foreach($intranetRoles as $role => $values) {
            $newvalue = $defaultvalue[$role];
            foreach ($values as $value => $usersarray) {
                if (in_array($intranetInfos['UserId'], $usersarray)) {
                    $newvalue = $value;
                    break;
                }
            }
            switch ($role) {
                case 'FILE_MAX_DOWNLOAD':
                    $confs[] = array('action.share','FILE_MAX_DOWNLOAD',$newvalue);
                    break;
                case 'FILE_MAX_EXPIRATION':
                    $confs[] = array('action.share','FILE_MAX_EXPIRATION',$newvalue);
                    if($newvalue != 0) $newvalue++;
                    $confs[] = array('access.fs','PURGE_AFTER_SOFT',$newvalue);
                    break;
                case 'PURGE_AFTER':
                    $confs[] = array('access.fs','PURGE_AFTER',$newvalue);
                    break;
                case 'DEFAULT_QUOTA':
                    $confs[] = array('meta.quota','DEFAULT_QUOTA',$newvalue.'M');
                    break;
                case 'UPLOAD_MAX_SIZE':
                    $confs[] = array('core.uploader','UPLOAD_MAX_SIZE',$newvalue.'M');
                    break;
            }
        }

        foreach($confs as $conf) {
            if ($userObject->personalRole->filterParameterValue($conf[0], $conf[1], AJXP_REPO_SCOPE_ALL, "") != $conf[2]) {
                $userObject->personalRole->setParameterValue($conf[0], $conf[1], $conf[2]);
                $changes = true;
            }
        }

        if ($changes) {
            $userObject->recomputeMergedRole();
            $userObject->save("superuser");
        }
    }

    //pour updateIntranetInfos()
    private function Intranet_SortRoles(&$roles)
    {
        foreach ($roles as $rolename => &$role) {
            switch ($rolename) {
                case 'FILE_MAX_EXPIRATION':
                case 'FILE_MAX_DOWNLOAD':
                case 'PURGE_AFTER':
                case 'DEFAULT_QUOTA':
                case 'UPLOAD_MAX_SIZE':
                default:
            	    uksort($role,function ($a,$b){
                        if ($a == 0) return -1;
                        if ($b == 0) return 1;
                        return $b - $a;
            	    });
            }
        }
    }

    //pour cron
    private function Intranet_GetPossibleRolesForContenu()
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "contenuId" => $this->getOption("INTRANETWS_CONTENUID"),
            "parameters" => array(
                "UserId" => '0000',
                "ApplicationName" => 'FiduShare',
                "UserName" => __FUNCTION__, // string
                "Language" => '', // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        $res = $soapClient->ContenuApplicatif_GetPossibleRolesForContenu($params)
            ->ContenuApplicatif_GetPossibleRolesForContenuResult->CRoleApplicatif;
        $roles = array();
        if (!isset($res)) return $roles; //0 role
        foreach ($res as $role) {
            $tag = explode("|", $role->Tag,2);
            if (!array_key_exists($tag[0], $roles)) $roles[$tag[0]] = array();
            $roles[$tag[0]][$tag[1]] = $this->Intranet_SearchUsersWithFilter($role->Id);
        }
        $this->Intranet_SortRoles($roles);
        return $roles;
    }

    private function Intranet_SearchUsersWithFilter($roleId)
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "searchUserFilter" => array(
        	    "UserFilter" => "HaveSpecificContenuRoleId",
                "UserFilterValue" => $this->getOption("INTRANETWS_CONTENUID").'|'.$roleId,
                "CanManage" => "Both",
                "UserStatus" => "Both", // ou both
                "OptionalNameFilterType" => "UserId", //don't care
                "PreFilter" => "None",
                "UserAccountStatus" => "All",
                "TNSStatus" => "All",
                "TestAccountStatus" => "All",
                "AddExportColumns" => false
            ),
            "beginningIndex" => -1,
            "nbMaxResults" => -1,
            "parameters" => array(
                "UserId" => '0000',
                "ApplicationName" => 'FiduShare',
                "UserName" => __FUNCTION__, // string
                "Language" => '', // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        $res = $soapClient->User_SearchUsersWithFilter($params)
            ->User_SearchUsersWithFilterResult->CUserLessReduced;
        if (!isset($res)) return array(); //0 user in role

        $users = array();
        foreach ($res as $user) {
            $users[] = $user->Id;
        }
        return $users;
    }

    //pour cron
    private function Intranet_ListAllUsers()
    {
        $soapClient = new SoapClient($this->getOption("INTRANETWS_URL"),
            array("features" => SOAP_SINGLE_ELEMENT_ARRAYS));
        $params = array(
            "searchUserFilter" => array(
                "UserFilter" => "NoFilter",
                "CanManage" => "Both",
                "UserStatus" => "Both",
                "OptionalNameFilterType" => "UserId", //don't care
                "PreFilter" => "None",
                "UserAccountStatus" => "All",
                "TNSStatus" => "All",
                "TestAccountStatus" => "All",
                "AddExportColumns" => false
            ),
            "beginningIndex" => -1,
            "nbMaxResults" => -1,
            "parameters" => array(
                "UserId" => '0000',
                "ApplicationName" => 'FiduShare',
                "UserName" => __FUNCTION__, // string
                "Language" => '', // string
                "UseTransaction" => false, // boolean
                "AdminMode" => false, // boolean
                "CheckDocumentAccess" => false, // boolean
                "Schema" => 'WebConfig', // SchemaName
                "DataSource" => '', // string
                "ClientIP" => '' // string
            )
        );
        $res = $soapClient->User_SearchUsersWithFilter($params)
        ->User_SearchUsersWithFilterResult->CUserLessReduced;
        if (!isset($res)) throw new Exception("0 user ???");

        $anMille = new DateTime("1000-01-01T00:00:00");
        $limit = new DateTime("-93 day");
        
        $users = array();
        foreach ($res as $user) {
            $ValidUntil = new DateTime($user->DateEndValidity);
            $toDelete = ($anMille < $ValidUntil) && ($ValidUntil < $limit);
            $users[$user->Id] = array(
                'Login' => $user->Login,
                'UserId' => $user->Id,
                'FullName' => $user->FullName,
                'Language' => $user->LanguageCode,
                'Mail' => $user->MailAddress,
                'toDelete' => $toDelete
            );
        }
        return $users;
    }

    public function Intranet_cron() {
        $this->logInfo('Cron', 'Debut Intranet_cron');
        // 1) clearexpiredfiles
        //$this->logInfo('Cron', 'Debut clearexpiredfiles');
        //todo
        //$this->logInfo('Cron', 'Fin clearexpiredfiles');
        
        
        // 2) delete/rename/update user 
        $this->logInfo('Cron', 'Debut recuperation info intranet');
        $intranet_users = $this->Intranet_ListAllUsers();
        $intranet_roles = $this->Intranet_GetPossibleRolesForContenu();
        $this->logInfo('Cron', 'Fin recuperation info intranet');
        
        $this->logInfo('Cron', 'Debut boucle delete/rename/update');
        $pydio_users = AuthService::listUsersFromConf();
        foreach ($pydio_users as $pydio_user) {
            try {
                $IntranetUserId = $pydio_user->personalRole->filterParameterValue("core.conf", "INTRANET_UserId", AJXP_REPO_SCOPE_ALL, "");
                if ($IntranetUserId == "") continue; //no id, this is not an intranet user

                $intranetInfos = $intranet_users[$IntranetUserId];
                if ($intranetInfos['toDelete'] === true) {
                    $this->logInfo('Cron', 'Delete '.$pydio_user->id);
                    AuthService::deleteUser($pydio_user->id);
                    continue;
                }
                
                $this->updateIntranetInfos($pydio_user, $intranetInfos, $intranet_roles);
                
            } catch (Exception $e) {
                $this->logError('Cron sync', $pydio_user->id.' : '.$e->getMessage().' line '.$e->getLine());
            }
        }
        $this->logInfo('Cron', 'Fin boucle delete/rename/update');
        
        /*
        // 3) purge
        $this->logInfo('Cron', 'Debut purge');
        $cronuser = AuthService::getLoggedUser();
        AuthService::disconnect();

        $pydio_users = AuthService::listUsers();
        foreach ($pydio_users as $pydio_user) {
            try {
                AuthService::logUser($pydio_user->id, "empty", true, false, "");
                $loggedUser = AuthService::getLoggedUser();
                $res = ConfService::switchUserToActiveRepository($loggedUser, '1');
                $plugAccessFs = AJXP_PluginsService::findPluginById('access.fs');
                $plugAccessFs->switchAction('purge',null,null);
                AuthService::disconnect();
            } catch (Exception $e) {
                $this->logError('Cron purge', $pydio_user->id.' : '.$e->getMessage().' line '.$e->getLine());
                AuthService::disconnect();
            }
        }
        AuthService::logUser($cronuser->id, "empty", true, false, "");
        $this->logInfo('Cron', 'Fin purge');
        */

        $this->logInfo('Cron', 'Fin Intranet_cron');
    }
}
