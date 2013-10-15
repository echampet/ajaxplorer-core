<?php

defined('AJXP_EXEC') or die( 'Access not allowed');

class FiducialNotifier extends AJXP_Plugin
{

    public function notify($type,$repository,$accessDriver)
    {
        switch ($type) {
        case 'file':
            $args = func_get_args();
            $data = $args[3];
            $url = $args[4];
            $filename = "'".$repository->display.":/".$data['FILE_PATH']."'";
            $expiration = new DateTime('@'.$data['EXPIRE_TIME']);
            $expiration = $expiration->format("d/m/y H:i");
            $limit = $data['DOWNLOAD_LIMIT'];
            
            $message = preg_split('/\r\n|\n|\r/', $this->pluginConf["BODY"]);
            $in = array('%filename%', '%url%', '%expiration%', '%limit%');
            $out = array($filename, $url, $expiration, $limit);
            $message = str_replace($in, $out, $message);
            break;
        default:
            return;
        }
       

 
        $headers   = array();
        $headers[] = 'From: '.$this->pluginConf["FROM"];


        $currentUser = AuthService::getLoggedUser();
        if ($currentUser != null) {
            $to = $currentUser->personalRole->filterParameterValue('core.conf', 'email', AJXP_REPO_SCOPE_ALL, "");
            mail($to, $this->pluginConf["SUBJECT"], implode("\r\n", $message), implode("\r\n", $headers));
        }

    }

    public function Intranet_cron() {
        $plug = AJXP_PluginsService::findPluginById('auth.fiducial');
        $plug->Intranet_cron();
    }

}
