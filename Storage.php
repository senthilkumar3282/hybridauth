<?php
/**
 * HybridAuth
 * 
 * An open source Web based Single-Sign-On PHP Library used to authentificates users with
 * major Web account providers and accessing social and data apis at Google, Facebook,
 * Yahoo!, MySpace, Twitter, Windows live ID, etc. 
 *
 * Copyright (c) 2009 (http://hybridauth.sourceforge.net)
 *
 * @package     Hybrid_Auth
 * @author      hybridAuth Dev Team
 * @copyright   Copyright (c) 2009, hybridAuth Dev Team.
 * @license     http://hybridauth.sourceforge.net/licenses.html under MIT and GPL
 * @link        http://hybridauth.sourceforge.net 
 */
 
/**
 * PHP Session storage 
 *
 * @author Zachy <hybridauth@gmail.com>
 */
class Hybrid_Storage {
	public function get($key, $expiration = false) 
	{
		$key = strtolower( $key );  

		if( isset( $_SESSION["HA::STORE"][$key] ) ) 
		{ 
			return unserialize( $_SESSION["HA::STORE"][$key] );  
		}

		return NULL; 
	}

	public function set( $key, $value )
	{
		$key = strtolower( $key ); 

		$_SESSION["HA::STORE"][$key] = serialize( $value ); 
	}

	function clear()
	{ 
		$_SESSION["HA::STORE"] = ARRAY(); 
	} 

	function delete($key)
	{
		$key = strtolower( $key );  

		if( isset( $_SESSION["HA::STORE"][$key] ) ) 
		{ 
			unset( $_SESSION["HA::STORE"][$key] );
		} 
	}

	function deleteMatch($key)
	{
		$key = strtolower( $key ); 

		if( isset( $_SESSION["HA::STORE"] ) && count( $_SESSION["HA::STORE"] ) ) {
			foreach( $_SESSION["HA::STORE"] as $k => $v ){ 
				if( strstr( $k, $key ) ){
					unset( $_SESSION["HA::STORE"][ $k ] ); 
				}
			}
		}
	}

	function getSessionData()
	{ 
		return serialize( $_SESSION["HA::STORE"] );
	}

	function restoreSessionData( $sessiondata = NULL )
	{ 
		$_SESSION["HA::STORE"] = unserialize( $sessiondata );
	}
}
