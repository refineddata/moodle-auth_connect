<?php

/**
 * @author Gary Menezes
 *
 * Authentication Plugin: ConnectPro
 *
 * This is a stub for updating connectPro and managing acp_passwords.  You cannot set a user's
 * authentication method to this or they will not be able to log in.
 *
 * 2011-06-1  File created.
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once( $CFG->dirroot.'/mod/connectmeeting/connectlib.php' );

/**
 * Plugin for no authentication - disabled user.
 */
class auth_plugin_connect extends auth_plugin_base {


    /**
     * Constructor.
     */
    function __construct() {
        $this->authtype = 'connect';
        $this->config   = get_config('auth/connect');
    }

    /**
     * If can login to Connect, create a moodle account.
     *
     */
    function user_login( $username, $password ) {
        global $CFG, $DB;
        
        if ( !isset( $this->config->addusers ) OR !$this->config->addusers ) return false;
        $user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id));

        // If already a moodle user by that username, just check against it.
        if ((!isset($this->config->acmaster) || !$this->config->acmaster) && $user) {
            if ( validate_internal_user_password( $user, $password ) ) return true;
        } else {
            // Try logging in with credentials given
            $connect = _connect_get_instance();
            $params = array( 'login' => $username, 'password' => $password );
            $result = $connect->connect_call( 'connectlogin', $params );
            if ( $result == true ) {
                if ( !empty($user) && ($password != connect_decrypt( $user->ackey )) ) {
                    $user->rawpass = $password;
                    connect_update_user( $user );
                }
                return true;
            }
            
        }

        return false;
    }

    function get_userinfo( $username ) {
        global $CFG, $DB;
        //$data = connect_get_user( $username );
        $connect = _connect_get_instance();
        $params = array( 'login' => $username );
        $data = $connect->connect_call( 'getuserinfo', $params );  
        if ( $data == false ) return false;
        $user = $this->object_to_array($data);
        return $user;
    }
    
    function object_to_array( $data ) {
        if ( is_object( $data ) ) {
            $result = array( );
            foreach ( $data as $key => $value ) {
                $result[$key] = $value ;
            }
            return $result;
        }
        return $data;
    }
    
    //Sync Roles
    function sync_roles( $user ) {
        global $CFG, $DB;
        // Only run if new user or if settings request it
        if ( !isset( $this->config->addadmins ) OR !$this->config->addadmins ) return true;
        // If Admin in Connect, Make Admin in Moodle          
        $connect = _connect_get_instance();
        $params = array( 'external_user_id' => $user->id);
        $result = $connect->connect_call( 'isuserinadmingroup', $params );
        if ( $result == true ) {
            $admins = array();
            foreach(explode(',', $CFG->siteadmins) as $admin) {
                $admin = (int) $admin;
                if ($admin) $admins[$admin] = $admin;
            }
            $admins[$user->id] = $user->id;
            set_config('siteadmins', implode(',', $admins));
        }
        return true;
    }

    /**
     * No password updates.
     */
    function user_update_password( $user, $newpassword ) {
        return false;
    }

    /**
     * No external data sync.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * No changing of password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * No password resetting.
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form( $config, $err, $user_fields ) {
        include "config.phtml";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config( $config ) {
        // set to defaults if undefined
        if ( !isset( $config->addadmins ) ) $config->addadmins = false;
        if ( !isset( $config->addusers ) )  $config->addusers  = false;
        if ( !isset( $config->acmaster ) )  $config->acmaster = false;

        // save settings
        set_config( 'addadmins', $config->addadmins, 'auth/connect' );
        set_config( 'addusers',  $config->addusers,  'auth/connect' );
        set_config( 'acmaster',  $config->acmaster, 'auth/connect');
        return true;
    }

    function user_authenticated_hook( &$user, $username, $password ) {
        global $CFG, $DB;
        require_once( $CFG->dirroot.'/mod/connectmeeting/connectlib.php' );
        $update = false;
        
        /*if ( $username == 'guest' ) return;

        if ( !empty( $CFG->connect_update_on_login ) ) {
            $user->rawpass = $password;
            connect_update_user( $user );
            $DB->update_record( 'user', $user );
        }
        if ( isset( $CFG->connect_aclogin_on_login ) AND $CFG->connect_aclogin_on_login ) connect_user_exec();*/
        
        return;
    }
    
}
?>
