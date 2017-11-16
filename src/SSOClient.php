<?php
	namespace Csa\Sso\Client;
	// SSO client support class.
	// (C) 2015 CubicleSoft.  All Rights Reserved.

	// Adds a PHP session layer for additional server-side security and reduced cookie size.
	class SSOClient extends ClientBase
	{
		private $sessionkey, $loggedinresult;

		public function SetCookieFixDomain($name, $value = "", $expires = 0, $path = "", $domain = "", $secure = false, $httponly = false)
		{
			if ($path === SSO_COOKIE_PATH && substr($name, 0, strlen(SSO_COOKIE_NAME)) === SSO_COOKIE_NAME)
			{
				// If cookies are written after SaveUserInfo() is called, the session will need to be reopened.
				$_SESSION[$this->sessionkey]["cookies"][substr($name, strlen(SSO_COOKIE_NAME))] = $value;
			}

			parent::SetCookieFixDomain($name, $value, $expires, $path, $domain, $secure, $httponly);
		}

		public function LoggedIn()
		{
			if (is_bool($this->loggedinresult))  return $this->loggedinresult;

			$this->loggedinresult = false;

			if (!parent::LoggedIn())  return false;

			// Validate the session cookie against the internal session data.
			if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"] && $this->user_info["loaded"])
			{
				$_SESSION[$this->sessionkey]["ipaddr"] = $this->user_cache["ipaddr"];
			}

			if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"] || (isset($_SESSION[$this->sessionkey]["cookies"]["_s"]) && isset($this->request[SSO_COOKIE_NAME . "_s"]) && $_SESSION[$this->sessionkey]["cookies"]["_s"] !== $this->request[SSO_COOKIE_NAME . "_s"]) || (isset($_SESSION[$this->sessionkey]["cookies"]["_v"]) && isset($this->request[SSO_COOKIE_NAME . "_v"]) && $_SESSION[$this->sessionkey]["cookies"]["_v"] !== $this->request[SSO_COOKIE_NAME . "_v"]))
			{
				// Assume the session was hijacked if the SSO server check has already happened.
				if ($this->user_info["loaded"])
				{
					// Avoid an infinite loop but force a logout.
					$_SESSION[$this->sessionkey]["cookies"] = array();

					return false;
				}

				// Validate the login.  Handle scenarios where the SSO Server is unavailable.
				$options = array(
					"sso_id" => $this->user_info["sso_id"],
					"expires" => (SSO_COOKIE_TIMEOUT > 0 && SSO_COOKIE_TIMEOUT < SSO_SERVER_SESSION_TIMEOUT ? SSO_COOKIE_TIMEOUT : SSO_SERVER_SESSION_TIMEOUT)
				);

				$result = $this->SendRequest("getlogin", $options);
				if (!$result["success"] && !isset($result["info"]))
				{
					$this->user_info["sso_id"] = "";

					return false;
				}
				if ($result["success"])
				{
					$this->ProcessLogin($result);

					$_SESSION[$this->sessionkey]["ipaddr"] = $this->user_cache["ipaddr"];
				}
				else if ($_SESSION[$this->sessionkey]["ipaddr"] !== $this->user_cache["ipaddr"])
				{
					$this->user_info["sso_id"] = "";

					return false;
				}
			}

			$this->loggedinresult = true;

			return true;
		}

		protected function ProcessLogin($info, $fromserver = false)
		{
			parent::ProcessLogin($info, $fromserver);

			// Reset local data set.  Otherwise clients might use stale content.
			$_SESSION[$this->sessionkey]["data"] = array();
		}

		public function Init($removekeys = array())
		{
			$this->sessionkey = "__sso_client_" . SSO_COOKIE_PATH . "_" . SSO_COOKIE_NAME;
			$this->loggedinresult = "invalid";

			@session_start();

			if (!isset($_SESSION[$this->sessionkey]))
			{
				$ipaddr = self::GetRemoteIP();

				$_SESSION[$this->sessionkey] = array(
					"cookies" => array(),
					"data" => array(),
					"ipaddr" => ($ipaddr["ipv4"] != "" && strlen($ipaddr["ipv4"]) < strlen($ipaddr["shortipv6"]) ? $ipaddr["ipv4"] : $ipaddr["shortipv6"]),
					"shortipv6" => $ipaddr["shortipv6"]
				);
			}

			parent::Init($removekeys);
		}

		public function CanRemoteLogin()
		{
			if (!parent::CanRemoteLogin())  return false;

			if ($_SESSION[$this->sessionkey]["shortipv6"] !== $this->ipaddr["shortipv6"] || (isset($_SESSION[$this->sessionkey]["cookies"]["_sr_id"]) && $_SESSION[$this->sessionkey]["cookies"]["_sr_id"] !== $this->request[SSO_COOKIE_NAME . "_sr_id"]) || (isset($_SESSION[$this->sessionkey]["cookies"]["_sr_t"]) && $_SESSION[$this->sessionkey]["cookies"]["_sr_t"] !== $this->request[SSO_COOKIE_NAME . "_sr_t"]))
			{
				// IP address changed or the cookies were hijacked.
				return false;
			}

			return true;
		}

		public function GetData($key, $default = false)
		{
			if (isset($_SESSION[$this->sessionkey]["data"][$key]))  return $_SESSION[$this->sessionkey]["data"][$key];

			return $default;
		}

		public function SetData($key, $value, $maxcookielen = 50)
		{
			if (isset($_SESSION[$this->sessionkey]["data"][$key]) && $_SESSION[$this->sessionkey]["data"][$key] === $value)  return false;

			$_SESSION[$this->sessionkey]["data"][$key] = $value;
			$this->user_cache["changed"] = true;

			if (isset($this->user_cache["dbdata"][$key]))
			{
				unset($this->user_cache["dbdata"][$key]);
				$this->user_cache["dbchanged"] = true;
				$this->user_cache["hasdb"] = count($this->user_cache["dbdata"]) > 0;
			}

			return true;
		}
	}
?>